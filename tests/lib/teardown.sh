# Generic teardown, sourced by the tests/e2e.sh dispatcher.
#
# The caller must set, before sourcing:
#   SERVERS - path to the .servers file (`id ip label zone` per line)
#
# Terminates every instance listed in SERVERS and removes the file. Manual — run
# only when you're done inspecting the servers.

do_teardown(){
  [[ -f "$SERVERS" ]] || { echo "No $SERVERS — nothing to tear down."; exit 0; }

  # The zone column doubles as the backend marker (the docker backend writes
  # `docker`). Feeding a docker fleet to `scw terminate` would fail on every row
  # and then delete the only record of it.
  if grep -qE '^[^ ]+ [^ ]+ [^ ]+ docker$' "$SERVERS"; then
    echo "Refusing: $SERVERS was written by the docker backend." >&2
    echo "Tear it down with: E2E_BACKEND=docker tests/e2e.sh <scenario> teardown" >&2
    exit 1
  fi

  local id ip label zone failed=0
  while read -r id ip label zone; do
    [[ -n "$id" ]] || continue
    echo ">> terminating $label  id=$id  ip=$ip  zone=$zone"
    # `terminate` deletes the server and frees its attached local volume + IP.
    scw instance server terminate "$id" zone="$zone" with-ip=true with-block=true || {
      echo "   (terminate failed for $id — check 'scw instance server list')"
      failed=1
    }
  done < "$SERVERS"

  echo
  if [[ "$failed" == 0 ]]; then
    rm -f "$SERVERS"
    echo "Removed $SERVERS. Verify with: scw instance server list"
  else
    # Keep the file: it is the only record of instances that are still billed.
    echo "Left $SERVERS in place: some instances could not be terminated." >&2
    exit 1
  fi
}

do_teardown
