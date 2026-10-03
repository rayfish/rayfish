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
#   ssh           2-peer mesh SSH (`ray firewall ssh`) allow/deny matrix (tests/e2e/ssh)
#   operator      2-peer unprivileged-client authority (`ray set-operator`) (tests/e2e/operator)
#   v4bridge      2-peer IPv4-only listener bridge over the mesh (tests/e2e/v4bridge)
#   reliability   4-peer full-mesh packet-loss test (ping + iperf3 UDP) (tests/e2e/reliability)
#   restore-offline 3-peer member-restore-with-coordinator-offline test (tests/e2e/restore-offline)
#   unpair        3-peer `ray unpair` device-cert revocation test (tests/e2e/unpair)
#   churn         4-peer churn test: repeated flap, kick + nuke delivered while a
#                 member is offline, health sweep (tests/e2e/churn)
#   exit-node     3-peer internet-gateway test: forwarding/NAT, full-tunnel egress,
#                 SO_MARK loop prevention, deny path (tests/e2e/exit-node)
#   bench         throughput / latency benchmark        (tests/bench)
#   all           every scenario above except bench: provision, run, then tear
#                 each fleet down before the next (one fleet live at a time)
#
# Actions:
#   run           (default) provision instances if needed, then run the scenario
#   provision     create the hosts only (-> <dir>/.servers)
#   teardown      destroy the hosts and remove .servers
#
# Backends (E2E_BACKEND, default digitalocean):
#   digitalocean  real droplets, one fleet per scenario (needs doctl + jq)
#   docker        local containers on one bridge (needs docker + /dev/net/tun).
#                 exit-node, reliability and bench need real hosts: distinct
#                 public IPs and a WAN baseline one bridge cannot provide.
#
# Each scenario's fleet (instance names + role labels) is declared in the
# registry below; the actual run steps live in <dir>/run.sh. The shared
# provision/teardown/assert bodies live in tests/lib/ and are sourced here.
#
# Env overrides: REGION/SIZE/IMAGE/DO_SSH_KEYS (droplet provision); E2E_DOCKER_*
# (docker provision, see tests/lib/docker.sh); SSH_KEY, KEEP_STATE (run);
# E2E_AUTO_TEARDOWN (auto-teardown after run; Docker also dumps failure diagnostics).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Exported: the `all` path re-invokes this script per scenario, and a plain shell
# variable would silently drop back to digitalocean halfway through.
export E2E_BACKEND="${E2E_BACKEND:-digitalocean}"

usage(){ sed -n '2,37p' "$0" | sed 's/^#\( \|$\)//'; exit "${1:-0}"; }

# Scenarios the docker backend cannot run faithfully (see tests/e2e/README.md).
DOCKER_UNSUPPORTED=(exit-node reliability bench)

# docker_supports <scenario> : exit 1 if the active backend can't run it.
docker_supports(){
  [[ "$E2E_BACKEND" != "docker" ]] && return 0
  local s
  for s in "${DOCKER_UNSUPPORTED[@]}"; do [[ "$1" == "$s" ]] && return 1; done
  return 0
}

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
    ssh)         DIR="$ROOT/tests/e2e/ssh"
                 NAMES=(rayfish-ssh-a rayfish-ssh-b)
                 LABELS=(srv-a srv-b) ;;
    operator)    DIR="$ROOT/tests/e2e/operator"
                 NAMES=(rayfish-op-a rayfish-op-b)
                 LABELS=(srv-a srv-b) ;;
    v4bridge)    DIR="$ROOT/tests/e2e/v4bridge"
                 NAMES=(rayfish-v4br-a rayfish-v4br-b)
                 LABELS=(srv-a srv-b) ;;
    reliability) DIR="$ROOT/tests/e2e/reliability"
                 NAMES=(rayfish-reli-a rayfish-reli-b rayfish-reli-c rayfish-reli-d)
                 LABELS=(srv-a srv-b srv-c srv-d) ;;
    restore-offline) DIR="$ROOT/tests/e2e/restore-offline"
                 NAMES=(rayfish-restore-a rayfish-restore-b rayfish-restore-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    unpair)      DIR="$ROOT/tests/e2e/unpair"
                 NAMES=(rayfish-unpair-a rayfish-unpair-b rayfish-unpair-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    churn)       DIR="$ROOT/tests/e2e/churn"
                 NAMES=(rayfish-churn-a rayfish-churn-b rayfish-churn-c rayfish-churn-d)
                 LABELS=(srv-a srv-b srv-c srv-d) ;;
    exit-node)   DIR="$ROOT/tests/e2e/exit-node"
                 NAMES=(rayfish-exit-a rayfish-exit-b rayfish-exit-c)
                 LABELS=(srv-a srv-b srv-c) ;;
    bench)       DIR="$ROOT/tests/bench"
                 NAMES=(rayfish-bench-a rayfish-bench-b)
                 LABELS=(srv-a srv-b) ;;
    *)           return 1 ;;
  esac
}

scenario="${1:-}"; action="${2:-run}"
case "$scenario" in -h|--help|help|"") usage 0 ;; esac

# `all`: run every functional scenario (bench excluded) end to end, tearing each
# fleet down before the next so at most one fleet is ever live. Reuses this same
# dispatcher per scenario (provision-if-needed + run, then teardown). Prints a
# pass/fail summary and exits non-zero if any scenario failed.
if [[ "$scenario" == all ]]; then
  all_scenarios=(device-cert connect firewall closed-net apply dns ssh operator v4bridge reliability restore-offline unpair churn exit-node)
  passed=(); failed=(); skipped=()
  hint="check 'doctl compute droplet list'"
  [[ "$E2E_BACKEND" == "docker" ]] && hint="check 'docker ps -a'"
  for s in "${all_scenarios[@]}"; do
    if ! docker_supports "$s"; then skipped+=("$s"); continue; fi
    echo "==================== $s ===================="
    if bash "$0" "$s" run; then
      passed+=("$s")
    else
      failed+=("$s")
    fi
    # Always tear the fleet down, pass or fail, before the next scenario.
    bash "$0" "$s" teardown || echo ">> warning: teardown failed for $s ($hint)"
  done
  echo "==================== e2e summary ===================="
  echo "passed (${#passed[@]}): ${passed[*]:-none}"
  echo "failed (${#failed[@]}): ${failed[*]:-none}"
  if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "skipped on the $E2E_BACKEND backend (${#skipped[@]}): ${skipped[*]}"
  fi
  if [[ ${#failed[@]} -eq 0 ]]; then exit 0; else exit 1; fi
fi

scenario_meta "$scenario" || { echo "unknown scenario: $scenario" >&2; usage 1; }

if ! docker_supports "$scenario"; then
  echo "$scenario does not run on the docker backend: it needs hosts with" >&2
  echo "distinct public IPs and a real WAN baseline (see tests/e2e/README.md)." >&2
  echo "Run it without E2E_BACKEND=docker." >&2
  exit 2
fi

SERVERS="$DIR/.servers"
NEXT="$0 $scenario run"   # printed by the backend's do_provision

# provision <how> : run the active backend's provisioner. The docker backend
# recreates its fleet on every run: device-cert and unpair never call `ray up`
# after deploying, so against an already-deployed fleet the daemon comes back in
# standby and every data-plane check fails. Containers are cheap; VMs are not.
provision(){
  if [[ "$E2E_BACKEND" == "docker" ]]; then
    DOCKER_ACTION=provision
    # shellcheck source=lib/docker.sh
    source "$ROOT/tests/lib/docker.sh"        # consumes NAMES/LABELS/SERVERS/NEXT
  else
    # shellcheck source=lib/provision.sh
    source "$ROOT/tests/lib/provision.sh"     # consumes NAMES/LABELS/SERVERS/NEXT
  fi
}

teardown(){
  if [[ "$E2E_BACKEND" == "docker" ]]; then
    DOCKER_ACTION=teardown
    # shellcheck source=lib/docker.sh
    source "$ROOT/tests/lib/docker.sh"      # consumes SERVERS/NAMES
  else
    # shellcheck source=lib/teardown.sh
    source "$ROOT/tests/lib/teardown.sh"    # consumes SERVERS
  fi
}

dump_diagnostics(){
  local scn="${1:-$scenario}"
  echo "==================== DIAGNOSTICS: $scn ===================="
  if [[ "$E2E_BACKEND" == "docker" ]]; then
    echo "--- Docker containers ---"
    # Connection timeouts do not bound a connected SSH session or Docker RPC.
    # Diagnostics must finish so an unresponsive node cannot prevent teardown.
    timeout --kill-after=2s 10s docker ps -a --filter "network=${E2E_DOCKER_NET:-rayfish-e2e}" 2>&1 || true
    if [[ -f "$SERVERS" ]]; then
      local id ip label z
      while read -r id ip label z; do
        [[ -n "$id" ]] || continue
        echo "--- Host: $label ($id, $ip) ---"
        echo "  [ray status]"
        timeout --kill-after=2s 10s ssh -n -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
          -i "${SSH_KEY:-$HOME/.ssh/id_ed25519}" "root@$ip" 'ray status' 2>&1 || true
        echo "  [journalctl -u rayfish]"
        timeout --kill-after=2s 10s docker exec "$id" journalctl -u rayfish -n 50 --no-pager 2>&1 || true
      done < "$SERVERS"
    fi
  fi
  echo "=========================================================="
}

case "$action" in
  provision)
    provision ;;
  teardown)
    ( teardown ) ;;
  run)
    if [[ "${E2E_AUTO_TEARDOWN:-0}" == "1" ]]; then
      # Guarded lifecycle: provisioning + scenario run + diagnostics + teardown.
      # Provisioning runs in a subshell with `set -e` isolated from conditional
      # contexts (which suppress errexit in Bash), while allowing the parent
      # to capture the exit status without exiting.
      run_status=0
      if [[ "$E2E_BACKEND" == "docker" || ! -f "$SERVERS" ]]; then
        [[ -f "$SERVERS" ]] || echo ">> no $SERVERS yet — provisioning first"
        set +e
        (
          set -e
          provision
        )
        run_status=$?
        set -e
      fi
      if [[ $run_status -eq 0 ]]; then
        set +e
        bash "$DIR/run.sh"
        run_status=$?
        set -e
      fi
      if [[ $run_status -ne 0 ]]; then
        echo ">> Scenario $scenario failed (exit code $run_status)."
        dump_diagnostics "$scenario" || true
      fi
      echo ">> Auto-teardown for $scenario (E2E_AUTO_TEARDOWN=1)..."
      teardown_status=0
      set +e
      (
        set -e
        teardown
      )
      teardown_status=$?
      set -e
      if [[ $teardown_status -ne 0 ]]; then
        echo ">> Teardown failed for $scenario (exit code $teardown_status)." >&2
      fi
      if [[ $run_status -ne 0 ]]; then
        exit "$run_status"
      elif [[ $teardown_status -ne 0 ]]; then
        exit "$teardown_status"
      else
        exit 0
      fi
    else
      if [[ "$E2E_BACKEND" == "docker" || ! -f "$SERVERS" ]]; then
        [[ -f "$SERVERS" ]] || echo ">> no $SERVERS yet — provisioning first"
        provision
      fi
      exec bash "$DIR/run.sh"
    fi ;;
  *)
    echo "unknown action: $action" >&2; usage 1 ;;
esac
