#!/usr/bin/env bash
# Regression checks for the direct-connect scenario's offline negative case.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
# shellcheck source=lib/common.sh
source "$ROOT/tests/lib/common.sh"
# Load the actual scenario helper without provisioning or executing its flow.
source <(sed -n '/^check_offline_contact(){/,/^}/p' "$ROOT/tests/e2e/connect/run.sh")

offline_case(){ (
  local mode="$1" expected="$2" rc=0
  local old_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local new_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  local calls="$TEST_TMP/calls"
  : > "$calls"
  retry_until(){ shift; eval "$*"; }
  status_json(){
    if [[ "$mode" == still_active ]]; then echo '{"active":true}'; else echo '{"active":false}'; fi
  }
  on(){
    case "$2" in
      'ray down') [[ "$mode" != standby_failure ]] ;;
      'ray contact rotate --json')
        echo rotation >> "$calls"
        case "$mode" in
          rotation_failure) printf '{"contact_id":"%s"}\n' "$new_id"; return 255 ;;
          malformed_json) echo invalid ;;
          missing_id) echo '{}' ;;
          empty_id) echo '{"contact_id":""}' ;;
          wrong_id_type) echo '{"contact_id":123}' ;;
          unsafe_id) echo '{"contact_id":"bbbbbbbbbbbbbbbbbbbb;echo bad"}' ;;
          unchanged_id) printf '{"contact_id":"%s"}\n' "$old_id" ;;
          *) printf '{"contact_id":"%s"}\n' "$new_id" ;;
        esac ;;
      "timeout --kill-after=5s 30s ray connect $new_id")
        echo connect >> "$calls"
        case "$mode" in
          unrelated_error) echo 'connect failed: cannot load configuration'; return 1 ;;
          success) echo 'connected'; return 0 ;;
          misleading_success) echo 'contact offline or unknown (could not resolve contact id)'; return 0 ;;
          expected_error_with_extra_text) echo 'configuration failed: contact offline or unknown (could not resolve contact id)'; return 1 ;;
          timeout) echo 'contact offline or unknown (could not resolve contact id)'; return 124 ;;
          ssh_failure) echo 'contact offline or unknown (could not resolve contact id)'; return 255 ;;
          *) printf '  ✗ connect failed\n    contact offline or unknown (could not resolve contact id)\n'; return 1 ;;
        esac ;;
      *) echo "unexpected command: $2" >&2; return 42 ;;
    esac
  }
  check_offline_contact src dst "$old_id" || rc=$?
  if [[ "$expected" == pass ]]; then
    [[ $rc == 0 && $FAILS == 0 ]] || return 1
    [[ $(grep -c '^connect$' "$calls") == 1 ]]
  else
    [[ $rc == 1 && $FAILS == 1 ]] || return 1
    case "$mode" in
      standby_failure|still_active)
        [[ ! -s "$calls" ]] ;;
      rotation_failure|malformed_json|missing_id|empty_id|wrong_id_type|unsafe_id|unchanged_id)
        if grep -q '^connect$' "$calls"; then return 1; fi ;;
    esac
  fi
) ; }

for mode in normal standby_failure still_active rotation_failure malformed_json \
            missing_id empty_id wrong_id_type unsafe_id unchanged_id unrelated_error \
            success misleading_success expected_error_with_extra_text timeout ssh_failure; do
  expected=fail
  [[ "$mode" != normal ]] || expected=pass
  if offline_case "$mode" "$expected" > "$TEST_TMP/output" 2>&1; then
    printf 'PASS offline contact: %s\n' "$mode"
  else
    cat "$TEST_TMP/output" >&2
    printf 'FAIL offline contact: %s\n' "$mode" >&2
    exit 1
  fi
done
