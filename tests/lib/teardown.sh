# Generic teardown, sourced by the tests/e2e.sh dispatcher.
#
# The caller must set, before sourcing:
#   SERVERS - path to the .servers file (`id ip label region` per line)
#
# Destroys every droplet listed in SERVERS and removes the file. Manual: run
# only when you're done inspecting the hosts.

do_teardown(){
  [[ -f "$SERVERS" ]] || { echo "No $SERVERS, nothing to tear down."; exit 0; }

  # The region column doubles as the backend marker (the docker backend writes
  # `docker`). Feeding a docker fleet to `doctl droplet delete` would fail on
  # every row and then delete the only record of it.
  if grep -qE '^[^ ]+ [^ ]+ [^ ]+ docker$' "$SERVERS"; then
    echo "Refusing: $SERVERS was written by the docker backend." >&2
    echo "Tear it down with: E2E_BACKEND=docker tests/e2e.sh <scenario> teardown" >&2
    exit 1
  fi

  command -v doctl >/dev/null || { echo "doctl not found"; exit 1; }

  local id ip label region failed=0
  while read -r id ip label region; do
    [[ -n "$id" ]] || continue
    echo ">> destroying $label  id=$id  ip=$ip  region=$region"
    # Droplet ids are global, so no region argument. --force skips the prompt;
    # deleting the droplet releases its public IPv4 and IPv6 with it.
    doctl compute droplet delete "$id" --force || {
      echo "   (delete failed for $id, check 'doctl compute droplet list')"
      failed=1
    }
  done < "$SERVERS"

  echo
  if [[ "$failed" == 0 ]]; then
    rm -f "$SERVERS"
    echo "Removed $SERVERS. Verify with: doctl compute droplet list"
  else
    # Keep the file: it is the only record of droplets that are still billed.
    echo "Left $SERVERS in place: some droplets could not be destroyed." >&2
    exit 1
  fi
}

do_teardown
