# Generic DigitalOcean provisioner, sourced by the tests/e2e.sh dispatcher.
#
# The caller must set, before sourcing:
#   NAMES  - array of droplet names (one per host)
#   LABELS - array of role labels (srv-a, srv-b, …), parallel to NAMES
#   SERVERS - path to the .servers file to write (`id ip label region` per line)
#   NEXT   - hint printed at the end ("Next: <scenario>/run.sh")
#
# Creates the droplets, waits for boot, resolves public IPs, and writes SERVERS.
# Re-running is a no-op while SERVERS exists (delete it to re-provision). Droplets
# are LEFT RUNNING; use the scenario's teardown to destroy them.
# Honors REGION / SIZE / IMAGE / DO_SSH_KEYS overrides.
#
# The fourth column is the region, and it doubles as the backend marker: the
# docker backend writes `docker` there and each backend refuses the other's file.

do_provision(){
  local REGION="${REGION:-fra1}"
  local SIZE="${SIZE:-s-1vcpu-1gb}"
  local IMAGE="${IMAGE:-ubuntu-22-04-x64}"

  # The region column doubles as the backend marker; don't drive a docker fleet
  # from the cloud path (or silently bill new droplets alongside it).
  if [[ -f "$SERVERS" ]] && grep -qE '^[^ ]+ [^ ]+ [^ ]+ docker$' "$SERVERS"; then
    echo "Refusing: $SERVERS was written by the docker backend." >&2
    echo "Tear it down first, or run with E2E_BACKEND=docker." >&2
    exit 1
  fi

  if [[ -f "$SERVERS" ]]; then
    echo "Found existing $SERVERS, skipping provisioning."
    echo "(delete it to provision a fresh set)"
    echo
    cat "$SERVERS"
    return 0
  fi

  command -v doctl >/dev/null || { echo "doctl not found (see tests/e2e/README.md)"; exit 1; }
  command -v jq    >/dev/null || { echo "jq not found";  exit 1; }
  doctl account get >/dev/null 2>&1 || {
    echo "doctl is not authenticated: run 'doctl auth init'" >&2
    exit 1
  }

  # DigitalOcean injects nothing unless --ssh-keys names it, so a droplet created
  # without this gets a mailed root password and refuses our key. Default to every
  # key on the account, which is what the harness needs: `just scp` runs bare
  # rsync/ssh with no -i, so the host has to accept ssh's default identity, and
  # closed-net/run.sh reassigns $KEY midway through its run.
  local keys="${DO_SSH_KEYS:-}"
  if [[ -z "$keys" ]]; then
    keys="$(doctl compute ssh-key list --format ID --no-header 2>/dev/null | paste -sd, -)"
  fi
  if [[ -z "$keys" ]]; then
    echo "No SSH keys on the DigitalOcean account, so the droplets would be unreachable." >&2
    echo "Add one with: doctl compute ssh-key import <name> --public-key-file ~/.ssh/id_ed25519.pub" >&2
    exit 1
  fi

  local tmp; tmp="$(mktemp)"
  # Every droplet already created is billed, and $tmp is the only record of it
  # until the `mv` below. So the trap keeps the partial fleet rather than
  # discarding it: `teardown` needs the ids, and "No .servers, nothing to tear
  # down" on a fleet that is running costs real money. See tests/lib/teardown.sh.
  trap 'if [[ -s "$tmp" ]]; then mv "$tmp" "$SERVERS"; \
          echo "   kept the partial fleet in $SERVERS; run teardown to remove it" >&2; \
        else rm -f "$tmp"; fi' EXIT

  local i name label json id ip ip6 no_v6=0
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    label="${LABELS[$i]}"
    echo ">> creating $name ($label)  [$SIZE $IMAGE $REGION]"
    # --enable-ipv6 is only settable at create time, and the exit-node suite
    # tunnels IPv6 and nothing else, so a fleet without it tests nothing there.
    json="$(doctl compute droplet create "$name" \
              --region "$REGION" --size "$SIZE" --image "$IMAGE" \
              --ssh-keys "$keys" --enable-ipv6 --wait --output json)"
    id="$(echo "$json" | jq -r '.[0].id // empty')"
    [[ -n "$id" ]] || { echo "   create failed for $name" >&2; exit 1; }
    ip="$(echo  "$json" | jq -r '[.[0].networks.v4[]? | select(.type=="public") | .ip_address] | first // empty')"
    ip6="$(echo "$json" | jq -r '[.[0].networks.v6[]? | .ip_address] | first // empty')"
    # --wait returns once the droplet is active, but the create response has been
    # known to predate the network block; re-read rather than write an empty IP.
    if [[ -z "$ip" || -z "$ip6" ]]; then
      json="$(doctl compute droplet get "$id" --output json)"
      [[ -n "$ip"  ]] || ip="$(echo  "$json" | jq -r '[.[0].networks.v4[]? | select(.type=="public") | .ip_address] | first // empty')"
      [[ -n "$ip6" ]] || ip6="$(echo "$json" | jq -r '[.[0].networks.v6[]? | .ip_address] | first // empty')"
    fi
    # The droplet exists and is billed even with no address on it, so record it
    # before bailing or teardown has no id to destroy. `-` keeps the column
    # count; teardown only needs the id.
    [[ -n "$ip" ]] || {
      echo "$id - $label $REGION" >> "$tmp"
      echo "   no public IPv4 for $name" >&2
      exit 1
    }
    echo "   id=$id  ip=$ip  ipv6=${ip6:-<none>}"
    [[ -n "$ip6" ]] || no_v6=1
    echo "$id $ip $label $REGION" >> "$tmp"
  done

  mv "$tmp" "$SERVERS"
  trap - EXIT
  echo
  if [[ "$no_v6" == 1 ]]; then
    echo "WARNING: at least one droplet has no public IPv6." >&2
    echo "The overlay is IPv6-only and exit-node/run.sh SKIPS its egress assertions" >&2
    echo "when a host cannot reach the v6 internet, so that suite would pass without" >&2
    echo "testing the tunnel. Check IPv6 availability in REGION=$REGION." >&2
    echo >&2
  fi
  echo "Wrote $SERVERS:"
  cat "$SERVERS"
  echo
  echo "Next:  ${NEXT:-run.sh}"
}

do_provision
