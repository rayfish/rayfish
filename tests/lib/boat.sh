# Boat sandbox backend, sourced by the tests/e2e.sh dispatcher when
# E2E_BACKEND=boat. Stands in for lib/provision.sh + lib/teardown.sh.
#
# The caller must set, before sourcing:
#   BOAT_ACTION - provision | teardown
#   NAMES, LABELS, SERVERS, NEXT - as for lib/provision.sh
#
# Each host is a Boat VM (https://boat.dev): KVM, systemd, /dev/net/tun. The
# harness reaches it as root over its public IPv6, so that address goes in
# SERVERS. Its IPv4 egress leaves through a public address of its own behind
# NAT, which is what exit-node checks. ufw is turned off so the hosts are as
# open as a droplet. The fourth column is `boat`, the backend marker.
#
# Env: BOAT_TYPE (default `default`), BOAT_HOURS (how long a VM stays on,
#      default 3).

export BOAT_NO_UPDATE=1

boat_refuse_other(){
  [[ -f "$SERVERS" ]] || return 0
  local marker; marker="$(awk 'NF >= 4 { print $4; exit }' "$SERVERS" 2>/dev/null)"
  if [[ -n "$marker" && "$marker" != boat ]]; then
    echo "Refusing: $SERVERS was written by another backend ($marker)." >&2
    echo "Tear that fleet down with its own E2E_BACKEND first." >&2
    exit 1
  fi
}

# boat_public_v6 <id> : the VM's global IPv6, the one root SSH answers on.
boat_public_v6(){
  boat ssh "$1" -- "ip -6 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | grep -v '^f[cd]' | head -1" 2>/dev/null \
    | grep -E '^[0-9a-f:]+$' | head -1
}

do_provision(){
  boat_refuse_other
  if [[ -f "$SERVERS" ]]; then
    echo "Found existing $SERVERS, skipping provisioning."
    echo "(tear it down to provision a fresh set)"
    echo
    cat "$SERVERS"
    return 0
  fi

  command -v boat >/dev/null || { echo "boat not found (https://boat.dev)"; exit 1; }
  command -v jq   >/dev/null || { echo "jq not found"; exit 1; }
  local key="${SSH_KEY:-$HOME/.ssh/id_ed25519}.pub"
  [[ -f "$key" ]] || { echo "no public key at $key"; exit 1; }

  # Not `local`, for the same reason as lib/provision.sh: the EXIT trap reads
  # it after `set -e` has popped the function's locals. Every VM already
  # created is billed, and this file is the only record of it.
  BOAT_TMP="$(mktemp)"
  trap 'if [[ -s "$BOAT_TMP" ]]; then mv "$BOAT_TMP" "$SERVERS"; \
          echo "   kept the partial fleet in $SERVERS; run teardown to remove it" >&2; \
        else rm -f "$BOAT_TMP"; fi' EXIT

  local i name label id ip
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    label="${LABELS[$i]}"
    echo ">> creating $name ($label)  [boat ${BOAT_TYPE:-default}]"
    id="$(boat new --type "${BOAT_TYPE:-default}" --name "$name" --json \
            | jq -r 'select(.event == "ready") | .id' | tail -1)"
    [[ -n "$id" && "$id" != null ]] || { echo "   create failed for $name" >&2; exit 1; }
    # Recorded before anything else can fail, so teardown can delete it.
    echo "$id - $label boat" >> "$BOAT_TMP"
    boat extend "$id" --hours "${BOAT_HOURS:-3}" >/dev/null
    boat scp "$key" "$id:/tmp/e2e.pub" >/dev/null
    boat ssh "$id" -- 'sudo sh -c "mkdir -p /root/.ssh && cat /tmp/e2e.pub >> /root/.ssh/authorized_keys \
      && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys"; sudo ufw disable >/dev/null 2>&1; true' >/dev/null 2>&1
    ip="$(boat_public_v6 "$id")"
    [[ -n "$ip" ]] || { echo "   no public IPv6 for $name" >&2; exit 1; }
    sed -i "s/^$id - /$id $ip /" "$BOAT_TMP"
    echo "   id=$id  ip=$ip"
    if ! wait_ssh "$ip"; then echo "   root SSH never answered on $ip" >&2; exit 1; fi
  done

  mv "$BOAT_TMP" "$SERVERS"
  trap - EXIT
  echo
  echo "Wrote $SERVERS:"
  cat "$SERVERS"
  echo
  echo "Next:  ${NEXT:-run.sh}"
}

# wait_ssh <ip> : up to a minute for root SSH with the harness key. Records
# the host key in the default known_hosts, which `just scp` checks with no
# options of its own; an address Boat handed out before may carry a stale one.
wait_ssh(){
  local n
  ssh-keygen -R "$1" >/dev/null 2>&1 || true
  for n in $(seq 1 30); do
    ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
      -o LogLevel=ERROR -i "${SSH_KEY:-$HOME/.ssh/id_ed25519}" \
      "root@$1" true 2>/dev/null && return 0
    sleep 2
  done
  return 1
}

do_teardown(){
  [[ -f "$SERVERS" ]] || { echo "No $SERVERS, nothing to tear down."; exit 0; }
  boat_refuse_other
  command -v boat >/dev/null || { echo "boat not found"; exit 1; }

  local id ip label marker failed=0
  while read -r id ip label marker; do
    [[ -n "$id" ]] || continue
    echo ">> deleting $label  id=$id  ip=$ip"
    boat delete "$id" --yes >/dev/null || {
      echo "   (delete failed for $id, check 'boat list')"
      failed=1
    }
  done < "$SERVERS"

  echo
  if [[ "$failed" == 0 ]]; then
    rm -f "$SERVERS"
    echo "Removed $SERVERS. Verify with: boat list"
  else
    # Keep the file: it is the only record of VMs that are still billed.
    echo "Left $SERVERS in place: some VMs could not be deleted." >&2
    exit 1
  fi
}

case "${BOAT_ACTION:-}" in
  provision) do_provision ;;
  teardown)  do_teardown ;;
  *) echo "boat.sh: set BOAT_ACTION=provision|teardown before sourcing" >&2; exit 1 ;;
esac
