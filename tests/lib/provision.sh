# Generic Scaleway provisioner, sourced by the tests/e2e.sh dispatcher.
#
# The caller must set, before sourcing:
#   NAMES  - array of Scaleway instance names (one per host)
#   LABELS - array of role labels (srv-a, srv-b, …), parallel to NAMES
#   SERVERS - path to the .servers file to write (`id ip label zone` per line)
#   NEXT   - hint printed at the end ("Next: <scenario>/run.sh")
#
# Creates the servers, waits for boot, resolves public IPs, and writes SERVERS.
# Re-running is a no-op while SERVERS exists (delete it to re-provision). Servers
# are LEFT RUNNING; use the scenario's teardown.sh to destroy them.
# Honors ZONE / TYPE / IMAGE overrides.

do_provision(){
  local ZONE="${ZONE:-fr-par-1}"
  local TYPE="${TYPE:-DEV1-S}"
  local IMAGE="${IMAGE:-ubuntu_jammy}"

  if [[ -f "$SERVERS" ]]; then
    echo "Found existing $SERVERS — skipping provisioning."
    echo "(delete it to provision a fresh set)"
    echo
    cat "$SERVERS"
    return 0
  fi

  command -v scw >/dev/null || { echo "scw not found"; exit 1; }
  command -v jq  >/dev/null || { echo "jq not found";  exit 1; }

  local tmp; tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT

  local i name label json id ip
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    label="${LABELS[$i]}"
    echo ">> creating $name ($label)  [$TYPE $IMAGE $ZONE]"
    json="$(scw instance server create \
              type="$TYPE" zone="$ZONE" image="$IMAGE" \
              name="$name" ip=new -w -o json)"
    id="$(echo "$json" | jq -r '.id')"
    ip="$(echo "$json" | jq -r '(.public_ip.address // (.public_ips[0].address) // empty)')"
    if [[ -z "$ip" || "$ip" == "null" ]]; then
      ip="$(scw instance server get "$id" zone="$ZONE" -o json \
              | jq -r '(.public_ip.address // (.public_ips[0].address))')"
    fi
    echo "   id=$id  ip=$ip"
    echo "$id $ip $label $ZONE" >> "$tmp"
  done

  mv "$tmp" "$SERVERS"
  trap - EXIT
  echo
  echo "Wrote $SERVERS:"
  cat "$SERVERS"
  echo
  echo "Next:  ${NEXT:-run.sh}"
}

do_provision
