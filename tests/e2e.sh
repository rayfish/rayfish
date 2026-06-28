#!/usr/bin/env bash
# Single entry point for the rayfish end-to-end / benchmark suites.
#
#   ./tests/e2e.sh <scenario> [action]
#
# Scenarios:
#   device-cert   3-peer device-cert / pairing test   (tests/e2e/device-cert)
#   connect       2-peer `ray connect` direct test     (tests/e2e/connect)
#   firewall      3-peer suggested-firewall + rule matrix (tests/e2e/firewall)
#   closed-net    3-peer admission + lifecycle commands (tests/e2e/closed-net)
#   apply         3-peer declarative `ray apply` deploy       (tests/e2e/apply)
#   dns           2-peer Magic DNS resolution + resolv.conf takeover (tests/e2e/dns)
#   bench         throughput / latency benchmark        (tests/bench)
#
# Actions:
#   run           (default) provision instances if needed, then run the scenario
#   provision     create the Scaleway instances only (-> <dir>/.servers)
#   teardown      destroy the instances and remove .servers
#
# Each scenario's fleet (instance names + role labels) is declared in the
# registry below; the actual run steps live in <dir>/run.sh. The shared
# provision/teardown/assert bodies live in tests/lib/ and are sourced here.
#
# Env overrides: ZONE/TYPE/IMAGE (provision); SSH_KEY, KEEP_STATE (run).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage(){ sed -n '2,22p' "$0" | sed 's/^#\( \|$\)//'; exit "${1:-0}"; }

# scenario_meta <scenario> : set DIR / NAMES / LABELS for a scenario, or return 1.
scenario_meta(){
  case "$1" in
    device-cert) DIR="$ROOT/tests/e2e/device-cert"
                 NAMES=(rayfish-e2e-a rayfish-e2e-b rayfish-e2e-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    connect)     DIR="$ROOT/tests/e2e/connect"
                 NAMES=(rayfish-connect-a rayfish-connect-b)
                 LABELS=(srv-a srv-b) ;;
    firewall)    DIR="$ROOT/tests/e2e/firewall"
                 NAMES=(rayfish-fw-a rayfish-fw-b rayfish-fw-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    closed-net)  DIR="$ROOT/tests/e2e/closed-net"
                 NAMES=(rayfish-closednet-a rayfish-closednet-b rayfish-closednet-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    apply)       DIR="$ROOT/tests/e2e/apply"
                 NAMES=(rayfish-apply-a rayfish-apply-b rayfish-apply-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    dns)         DIR="$ROOT/tests/e2e/dns"
                 NAMES=(rayfish-dns-a rayfish-dns-b)
                 LABELS=(srv-a srv-b) ;;
    bench)       DIR="$ROOT/tests/bench"
                 NAMES=(rayfish-bench-a rayfish-bench-b)
                 LABELS=(srv-a srv-b) ;;
    *)           return 1 ;;
  esac
}

scenario="${1:-}"; action="${2:-run}"
case "$scenario" in -h|--help|help|"") usage 0 ;; esac
scenario_meta "$scenario" || { echo "unknown scenario: $scenario" >&2; usage 1; }

SERVERS="$DIR/.servers"
NEXT="$0 $scenario run"   # printed by lib/provision.sh's do_provision

case "$action" in
  provision)
    # shellcheck source=lib/provision.sh
    source "$ROOT/tests/lib/provision.sh" ;;   # consumes NAMES/LABELS/SERVERS/NEXT
  teardown)
    # shellcheck source=lib/teardown.sh
    source "$ROOT/tests/lib/teardown.sh" ;;    # consumes SERVERS
  run)
    if [[ ! -f "$SERVERS" ]]; then
      echo ">> no $SERVERS yet — provisioning first"
      # shellcheck source=lib/provision.sh
      source "$ROOT/tests/lib/provision.sh"
    fi
    exec bash "$DIR/run.sh" ;;
  *)
    echo "unknown action: $action" >&2; usage 1 ;;
esac
