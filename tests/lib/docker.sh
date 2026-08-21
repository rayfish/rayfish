# Local Docker backend, sourced by the tests/e2e.sh dispatcher when
# E2E_BACKEND=docker. Stands in for lib/provision.sh + lib/teardown.sh.
#
# The caller must set, before sourcing:
#   DOCKER_ACTION - provision | teardown
#   NAMES   - array of container names (one per host)   [provision]
#   LABELS  - array of role labels (srv-a, srv-b, …)    [provision]
#   SERVERS - path to the .servers file (`id ip label region` per line)
#   NEXT    - hint printed at the end                    [provision]
#
# Each "host" is a container running systemd as PID 1 with sshd on 0.0.0.0:22,
# on one user-defined bridge. That is all the scenario scripts ask for: they
# only ever reach a host as `ssh root@<ip>` and deploy with rsync + systemctl.
# The .servers format is identical to the cloud backend's, with the container
# name as the id and `docker` in the region column. That column is the backend
# marker, and it is what keeps the two backends off each other's fleets.
#
# Env: E2E_DOCKER_IMAGE / _NET / _SUBNET / _SUBNET6 override the names,
#      E2E_DOCKER_REBUILD=1 forces an image rebuild,
#      E2E_DOCKER_REUSE=1 keeps a live fleet instead of recreating it,
#      E2E_DOCKER_MDNS=1 leaves mDNS enabled on the nodes.

DOCKER_IMAGE="${E2E_DOCKER_IMAGE:-rayfish-e2e-node}"
DOCKER_NET="${E2E_DOCKER_NET:-rayfish-e2e}"
# Must avoid the overlay range (200::/7), which covers the magic resolver at
# 200::53 too, or the nodes would route mesh traffic straight out the bridge.
DOCKER_SUBNET="${E2E_DOCKER_SUBNET:-172.31.66.0/24}"
DOCKER_SUBNET6="${E2E_DOCKER_SUBNET6:-fd00:e2e::/64}"
DOCKER_CTX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../docker" && pwd)"

# servers_backend <servers-file> : echo the marker in the first row's region
# column (the backend that wrote the file), or nothing.
servers_backend(){
  [[ -f "$1" ]] || return 0
  local id ip label marker
  while read -r id ip label marker; do
    [[ -n "${marker:-}" ]] && { echo "$marker"; return 0; }
  done < "$1"
}

# authorized_keys_file : collect the public keys ssh would offer as a default
# identity into a temp file. `just scp` (justfile) runs bare `rsync`/`ssh` with
# no -i, and closed-net/run.sh reassigns $KEY midway through its run, so the
# nodes have to accept the default identity, not just $SSH_KEY.
authorized_keys_file(){
  local out; out="$(mktemp)"
  local k
  for k in "$HOME"/.ssh/id_*.pub "${SSH_KEY:-$HOME/.ssh/id_ed25519}.pub"; do
    [[ -f "$k" ]] && cat "$k" >> "$out"
  done
  sort -u "$out" -o "$out"
  if [[ ! -s "$out" ]]; then
    rm -f "$out"
    echo "no ssh public key found (looked for ~/.ssh/id_*.pub)" >&2
    echo "generate one with: ssh-keygen -t ed25519" >&2
    exit 1
  fi
  echo "$out"
}

ensure_image(){
  if [[ "${E2E_DOCKER_REBUILD:-0}" == "1" ]] || ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo ">> building $DOCKER_IMAGE from $DOCKER_CTX"
    docker build -q -t "$DOCKER_IMAGE" "$DOCKER_CTX" >/dev/null
  fi
}

ensure_network(){
  docker network inspect "$DOCKER_NET" >/dev/null 2>&1 && return 0
  echo ">> creating network $DOCKER_NET ($DOCKER_SUBNET, $DOCKER_SUBNET6)"
  docker network create --ipv6 \
    --subnet "$DOCKER_SUBNET" --subnet "$DOCKER_SUBNET6" "$DOCKER_NET" >/dev/null
}

# container_ip <name> : the container's address on our bridge.
container_ip(){
  docker inspect -f "{{ (index .NetworkSettings.Networks \"$DOCKER_NET\").IPAddress }}" "$1" 2>/dev/null
}

# fleet_is_live <name...> : exit 0 iff every container exists and is running.
fleet_is_live(){
  local n state
  for n in "$@"; do
    state="$(docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null || echo false)"
    [[ "$state" == "true" ]] || return 1
  done
}

# start_node <name> <label> <authorized-keys-file> : (re)create one node.
start_node(){
  local name="$1" label="$2" keys="$3"
  docker rm -f "$name" >/dev/null 2>&1 || true
  # --privileged: systemd needs to write its own cgroups. No -v /sys/fs/cgroup:
  #   that is the cgroup-v1 recipe and on a v2 host it hands the container a
  #   writable view of the *host* tree; Docker already mounts a correctly-rooted
  #   cgroup2 fs for privileged containers.
  # container=docker: Docker sets none of the markers systemd looks for, and a
  #   systemd that thinks it is on bare metal runs udev-trigger/modules-load
  #   against the host's /dev under --privileged.
  # disable_ipv6=0 on both all and default: tun::create unconditionally adds the
  #   overlay /128 and the daemon dies if it can't, and a freshly created
  #   interface inherits conf.default.
  docker run -d \
    --name "$name" --hostname "$label" \
    --network "$DOCKER_NET" \
    --privileged --cgroupns=private \
    --env container=docker \
    --tmpfs /run:rw,exec,mode=755 --tmpfs /run/lock:rw,mode=1777 \
    --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --stop-signal SIGRTMIN+3 \
    "$DOCKER_IMAGE" >/dev/null

  # docker cp preserves the source uid, and sshd's StrictModes rejects an
  # authorized_keys the account doesn't own.
  docker cp "$keys" "$name:/root/.ssh/authorized_keys" >/dev/null
  docker exec "$name" chown root:root /root/.ssh/authorized_keys
  docker exec "$name" chmod 600 /root/.ssh/authorized_keys

  # Docker always writes `nameserver 127.0.0.11` on a user-defined network and
  # treats --dns as that embedded resolver's forwarders. The daemon's direct-mode
  # DNS takeover refuses unless it captures an upstream that answers, so give the
  # node real resolvers. In place, the way the daemon writes it: the file is a
  # bind mount and cannot be replaced.
  docker exec "$name" sh -c \
    'printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf'

  if [[ "${E2E_DOCKER_MDNS:-0}" == "1" ]]; then
    docker exec "$name" rm -f /etc/systemd/system/rayfish.service.d/e2e.conf
  fi
}

# wait_node_ssh <ip> : block until the node accepts ssh, or give up.
wait_node_ssh(){
  local ip="$1" _
  for _ in $(seq 1 60); do
    ssh -n -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes \
        "root@$ip" true 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

do_provision(){
  command -v docker >/dev/null || { echo "docker not found"; exit 1; }
  [[ -c /dev/net/tun ]] || { echo "/dev/net/tun missing on this host (modprobe tun)"; exit 1; }

  local marker; marker="$(servers_backend "$SERVERS")"
  if [[ -n "$marker" && "$marker" != "docker" ]]; then
    echo ">> $SERVERS is a cloud fleet (region $marker), replacing it with a docker fleet"
    echo "   (tear that fleet down separately if it is still running)"
    rm -f "$SERVERS"
  fi

  if [[ "${E2E_DOCKER_REUSE:-0}" == "1" && -f "$SERVERS" ]] && fleet_is_live "${NAMES[@]}"; then
    echo "Reusing the live fleet in $SERVERS (E2E_DOCKER_REUSE=1)."
    cat "$SERVERS"
    return 0
  fi

  ensure_image
  ensure_network

  local keys; keys="$(authorized_keys_file)"
  trap 'rm -f "$keys"' EXIT

  local tmp; tmp="$(mktemp)"
  local i name label ip
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    label="${LABELS[$i]}"
    echo ">> starting $name ($label)  [$DOCKER_IMAGE on $DOCKER_NET]"
    start_node "$name" "$label" "$keys"
    ip="$(container_ip "$name")"
    if [[ -z "$ip" ]]; then
      echo "   could not resolve an address for $name on $DOCKER_NET"; exit 1
    fi
    # Bridge addresses get recycled across fleets with fresh host keys, and
    # `just scp` uses the default known_hosts. Drop any stale entry first.
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    echo "   name=$name  ip=$ip"
    if ! wait_node_ssh "$ip"; then echo "   sshd never came up on $name"; exit 1; fi
    echo "$name $ip $label docker" >> "$tmp"
  done

  mv "$tmp" "$SERVERS"
  rm -f "$keys"
  trap - EXIT
  echo
  echo "Wrote $SERVERS:"
  cat "$SERVERS"
  echo
  echo "Next:  ${NEXT:-run.sh}"
}

do_teardown(){
  [[ -f "$SERVERS" ]] || { echo "No $SERVERS — nothing to tear down."; exit 0; }

  local marker; marker="$(servers_backend "$SERVERS")"
  if [[ "$marker" != "docker" ]]; then
    echo "Refusing: $SERVERS is a cloud fleet (region ${marker:-unknown}), not docker." >&2
    echo "Tear it down with: E2E_BACKEND=digitalocean tests/e2e.sh <scenario> teardown" >&2
    exit 1
  fi

  local failed=0 id ip label z
  while read -r id ip label z; do
    [[ -n "$id" ]] || continue
    echo ">> removing $label  name=$id  ip=$ip"
    docker rm -f "$id" >/dev/null 2>&1 || { echo "   (removal failed for $id)"; failed=1; }
  done < "$SERVERS"

  if [[ "$failed" == 0 ]]; then
    rm -f "$SERVERS"
    echo "Removed $SERVERS."
  else
    echo "Left $SERVERS in place: some containers could not be removed." >&2
  fi

  # Drop the bridge once the last fleet is gone.
  if docker network inspect "$DOCKER_NET" >/dev/null 2>&1; then
    local attached
    attached="$(docker network inspect -f '{{len .Containers}}' "$DOCKER_NET" 2>/dev/null || echo 1)"
    if [[ "$attached" == "0" ]]; then
      docker network rm "$DOCKER_NET" >/dev/null 2>&1 && echo "Removed network $DOCKER_NET."
    fi
  fi
}

case "${DOCKER_ACTION:-}" in
  provision) do_provision ;;
  teardown)  do_teardown ;;
  *) echo "docker.sh: set DOCKER_ACTION=provision|teardown before sourcing" >&2; exit 1 ;;
esac
