# Generic teardown, sourced by the tests/e2e.sh dispatcher.
#
# The caller must set, before sourcing:
#   SERVERS - path to the .servers file (`id ip label zone` per line)
#
# Terminates every instance listed in SERVERS and removes the file. Manual — run
# only when you're done inspecting the servers.

do_teardown(){
  [[ -f "$SERVERS" ]] || { echo "No $SERVERS — nothing to tear down."; exit 0; }

  local id ip label zone
  while read -r id ip label zone; do
    [[ -n "$id" ]] || continue
    echo ">> terminating $label  id=$id  ip=$ip  zone=$zone"
    # `terminate` deletes the server and frees its attached local volume + IP.
    scw instance server terminate "$id" zone="$zone" with-ip=true with-block=true || \
      echo "   (terminate failed for $id — check 'scw instance server list')"
  done < "$SERVERS"

  rm -f "$SERVERS"
  echo
  echo "Removed $SERVERS. Verify with: scw instance server list"
}

do_teardown
