#!/usr/bin/env bash
# Unprivileged-client authority (`ray set-operator`) e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `operator`; carries the two
#          unprivileged local users the checks run as
#   srv-b  member; the far end that makes a mutation observable on the wire
#
# The daemon runs as root and the IPC socket is world-connectable on purpose:
# authority is a per-request SO_PEERCRED check in `Daemon::check_authorized`,
# not the socket's file mode. That split is only testable with a real second
# local user talking to a real daemon over a real socket, which is what this
# scenario supplies:
#
#   reads are open to any local user  ->  mutations are denied with a message
#   naming the fix  ->  a non-root user cannot grant itself operator  ->  root
#   grants alice  ->  alice mutates for real (config + firewall, verified on
#   srv-b's packets)  ->  mallory is still denied, and neither can alice pass
#   the grant on  ->  the grant survives a daemon restart.
#
# Reads tests/e2e/operator/.servers (written by provision.sh). Re-runnable.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

NET=operator
OPUSER=alice          # the user root promotes to operator
NOUSER=mallory        # the user that is never authorized
PROBE_PORT=18099      # the port the operator-installed rule opens

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }
A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

# as <ip> <user> <command...> : run a command on <ip> as an unprivileged local
# user, combined output on stdout, the command's own exit status returned.
# `su` rather than sudo: the image has no sudo, and root needs no password.
# Keep the command free of single quotes — it is passed through one.
as(){
  local ip="$1" user="$2"; shift 2
  on "$ip" "su -s /bin/bash $user -c '$*' 2>&1"
}

# denied <output> : exit 0 if the daemon refused the request with the wording a
# non-operator is meant to see. The message is half the feature: a bare failure
# leaves the user with no way to fix it, so the command it names is asserted too.
denied(){
  echo "$1" | grep -qi 'permission denied' && echo "$1" | grep -q 'set-operator'
}

# ---------------------------------------------------------------------------
step "0. wait for SSH on both hosts, deploy, bring the VPN up"
wait_all_ssh "$A" "$B"
seed_known_hosts "$A" "$B"
reset_state "$A" "$B"
deploy_all "$ROOT" "$A" "$B"
for h in "$A" "$B"; do on "$h" 'ray up' >/dev/null 2>&1 || true; done
wait_daemons "$A" "$B"

# ---------------------------------------------------------------------------
step "1. srv-a creates the closed network; srv-b joins via invite"
on "$A" "ray create --name $NET --hostname srv-a" | strip | sed 's/^/   a| /'
INV_B="$(mint_invite "$A" "$NET" srv-b)"
[[ -n "$INV_B" ]] && pass "minted invite for srv-b" || fail "invite mint failed"
on "$B" "ray join $INV_B --hostname srv-b" 2>&1 | strip | sed 's/^/   b| /'
wait_roster "$A" srv-b

A_IP="$(my_ip "$A" "$NET")" || { summary; }
B_IP="$(my_ip "$B" "$NET")" || { summary; }
echo "   A mesh ip=$A_IP  B mesh ip=$B_IP"
png "$B" "$A_IP" "srv-b -> srv-a baseline"

# ---------------------------------------------------------------------------
step "2. create two unprivileged users on srv-a"
for u in "$OPUSER" "$NOUSER"; do
  on "$A" "id -u $u >/dev/null 2>&1 || useradd -m -s /bin/bash $u"
done
OP_UID="$(on "$A" "id -u $OPUSER" | tr -d '[:space:]')"
NO_UID="$(on "$A" "id -u $NOUSER" | tr -d '[:space:]')"
if [[ -n "$OP_UID" && -n "$NO_UID" && "$OP_UID" != "$NO_UID" ]]; then
  pass "two unprivileged users on srv-a ($OPUSER=$OP_UID $NOUSER=$NO_UID)"
else
  fail "could not create the unprivileged users"; summary
fi
# The config tree is root:rayfish 0750, so neither user can read it directly:
# whatever they report has to have come over IPC from the daemon.
if as "$A" "$OPUSER" "cat /etc/rayfish/settings.toml" >/dev/null 2>&1; then
  fail "$OPUSER can read /etc/rayfish directly (config tree is not private)"
else
  pass "the config tree is unreadable to an unprivileged user"
fi

# ---------------------------------------------------------------------------
step "3. reads are open to any local user"
OUT="$(as "$A" "$OPUSER" "ray status --json")"; rc=$?
NETS="$(echo "$OUT" | jq -r '(.networks // [])[].name' 2>/dev/null | tr '\n' ' ')"
if [[ $rc -eq 0 ]] && echo "$NETS" | grep -qw "$NET"; then
  pass "$OPUSER can read 'ray status --json' (networks: ${NETS% })"
else
  fail "$OPUSER could not read status (rc=$rc, networks='${NETS% }')"
fi
# The peer list is the part that can only have come from the running daemon:
# a reader that fabricated an empty config would report a network with no peers.
SEEN="$(echo "$OUT" | jq -r --arg n "$NET" \
  '(.networks // []) | map(select(.name == $n)) | [.[].peers[].hostname] | join(",")' 2>/dev/null)"
[[ "$SEEN" == *srv-b* ]] \
  && pass "$OPUSER's status carries the daemon's roster (peers: $SEEN)" \
  || fail "$OPUSER's status has no peers (got '$SEEN') — not the daemon's view"

for cmd in "ray firewall show --json" "ray config get mdns" "ray connections"; do
  if as "$A" "$NOUSER" "$cmd" >/dev/null 2>&1; then
    pass "$NOUSER can run the open read: $cmd"
  else
    fail "$NOUSER was refused an open read: $cmd"
  fi
done

# A reader must never build the config tree it is reporting on: creating it is
# the daemon's job, and a reader that does it ends up reporting the directory it
# just made as the daemon's. On Linux the platform path is the fixed
# /etc/rayfish, which the running daemon already made, so point the client at a
# path that does not exist and check nothing appears there. That is the same
# code (`config_dir_for_read` vs `config_dir`) the macOS home-directory case
# runs through, reachable here.
PROBE_DIR=/tmp/ray-reader-probe
on "$A" "rm -rf $PROBE_DIR"
as "$A" "$OPUSER" "RAYFISH_CONFIG_DIR=$PROBE_DIR ray status" >/dev/null 2>&1
if on "$A" "test -e $PROBE_DIR"; then
  fail "an unprivileged read created $PROBE_DIR (reader called config_dir())"
else
  pass "an unprivileged read creates no config tree of its own"
fi

# And it leaves the daemon's tree exactly as it found it.
BEFORE="$(on "$A" "stat -c '%a %U:%G' /etc/rayfish" | tr -d '\r')"
as "$A" "$NOUSER" "ray status" >/dev/null 2>&1
as "$A" "$NOUSER" "ray firewall show" >/dev/null 2>&1
AFTER="$(on "$A" "stat -c '%a %U:%G' /etc/rayfish" | tr -d '\r')"
[[ "$BEFORE" == "$AFTER" ]] \
  && pass "unprivileged reads leave /etc/rayfish untouched ($AFTER)" \
  || fail "an unprivileged read changed /etc/rayfish ($BEFORE -> $AFTER)"

# ---------------------------------------------------------------------------
step "4. mutations are denied for a non-operator"
OUT="$(as "$A" "$OPUSER" "ray config set mdns on")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -ne 0 ]] && pass "ray config set exits non-zero for a non-operator" \
                || fail "ray config set exited 0 for a non-operator"
denied "$OUT" && pass "the refusal names the fix (sudo ray set-operator)" \
              || fail "refusal did not name 'permission denied' + set-operator: $OUT"

MDNS="$(on "$A" "ray config get mdns --json" | jq -r '.mdns // empty')"
[[ "$MDNS" != "on" ]] && pass "the setting is unchanged (mdns=$MDNS)" \
                      || fail "a denied 'config set' still changed the setting"

OUT="$(as "$A" "$OPUSER" "ray firewall add in allow -p tcp -P $PROBE_PORT")"
echo "$OUT" | sed 's/^/   alice| /'
denied "$OUT" && pass "ray firewall add is denied for a non-operator" \
              || fail "ray firewall add was not denied: $OUT"

# `ray down` would put the node on standby and take the rest of the run with it,
# which is exactly why it is worth proving denied rather than assuming it.
OUT="$(as "$A" "$OPUSER" "ray down")"
echo "$OUT" | sed 's/^/   alice| /'
denied "$OUT" && pass "ray down is denied for a non-operator" \
              || fail "ray down was not denied: $OUT"
png "$B" "$A_IP" "srv-a is still up after the denied 'ray down'"

# ---------------------------------------------------------------------------
step "5. a non-root user cannot grant itself operator"
OUT="$(as "$A" "$OPUSER" "ray set-operator $OPUSER")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -ne 0 ]] && pass "self-grant exits non-zero" || fail "self-grant exited 0"
if echo "$OUT" | grep -qi 'permission denied' && echo "$OUT" | grep -qiE 'root|sudo'; then
  pass "the refusal says the grant is root's to make"
else
  fail "self-grant refusal did not name root: $OUT"
fi
OUT="$(as "$A" "$OPUSER" "ray config set mdns on")"
denied "$OUT" && pass "$OPUSER is still not authorized after the attempt" \
              || fail "the self-grant took effect: $OUT"

# ---------------------------------------------------------------------------
step "6. root grants operator to $OPUSER"
OUT="$(on "$A" "ray set-operator $OPUSER" 2>&1)"; rc=$?
echo "$OUT" | strip | sed 's/^/   a| /'
[[ $rc -eq 0 ]] && pass "sudo ray set-operator $OPUSER succeeded" \
                || fail "root could not set the operator (rc=$rc): $OUT"

# ---------------------------------------------------------------------------
step "7. the operator can mutate — settings and firewall, for real"
OUT="$(as "$A" "$OPUSER" "ray config set mdns on")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -eq 0 ]] && pass "$OPUSER can now run 'ray config set'" \
                || fail "$OPUSER still refused after the grant (rc=$rc): $OUT"
MDNS="$(on "$A" "ray config get mdns --json" | jq -r '.mdns // empty')"
[[ "$MDNS" == "on" ]] && pass "the daemon persisted the operator's change (mdns=on)" \
                      || fail "the operator's change did not stick (mdns=$MDNS)"
# Put it back: the fleet shares one bridge and mDNS gives every node a discovery
# shortcut no real fleet has (see tests/docker/Dockerfile).
as "$A" "$OPUSER" "ray config set mdns off" >/dev/null 2>&1

# The data-plane half: a rule the operator installs has to reach the packet path,
# not just the config file. Closed first, open after.
start_tcp_listener "$A" "$PROBE_PORT"
fw_denies "$B" "$A_IP" "$PROBE_PORT" "port closed before the operator's rule"
OUT="$(as "$A" "$OPUSER" "ray firewall add in allow -p tcp -P $PROBE_PORT")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -eq 0 ]] && pass "$OPUSER can install a firewall rule" \
                || fail "$OPUSER could not install a rule (rc=$rc): $OUT"
fw_allows "$B" "$A_IP" "$PROBE_PORT" "the operator's rule reached the data plane"
stop_tcp_listener "$A" "$PROBE_PORT"

# ---------------------------------------------------------------------------
step "8. the grant is one UID, and it does not pass on"
OUT="$(as "$A" "$NOUSER" "ray config set mdns on")"; rc=$?
echo "$OUT" | sed 's/^/   mallory| /'
[[ $rc -ne 0 ]] && denied "$OUT" \
  && pass "$NOUSER is still denied while $OPUSER is the operator" \
  || fail "the grant leaked to another user: $OUT"
OUT="$(as "$A" "$NOUSER" "ray status --json")"
echo "$OUT" | jq -e '.networks' >/dev/null 2>&1 \
  && pass "$NOUSER can still read (a denial is not a lockout)" \
  || fail "$NOUSER lost read access"

OUT="$(as "$A" "$OPUSER" "ray set-operator $NOUSER")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -ne 0 ]] && pass "the operator cannot hand the grant on (exits non-zero)" \
                || fail "the operator granted operator to another user"
OUT="$(as "$A" "$NOUSER" "ray config set mdns on")"
denied "$OUT" && pass "$NOUSER is still denied after that attempt" \
              || fail "the operator's grant to $NOUSER took effect: $OUT"

# ---------------------------------------------------------------------------
step "9. the grant survives a daemon restart"
on "$A" 'systemctl restart rayfish' >/dev/null 2>&1
if retry_until 60 "on '$A' 'ray status' >/dev/null 2>&1"; then
  pass "daemon back after restart"
else
  fail "daemon did not come back after restart"; summary
fi
OUT="$(as "$A" "$OPUSER" "ray config set mdns off")"; rc=$?
echo "$OUT" | sed 's/^/   alice| /'
[[ $rc -eq 0 ]] && pass "$OPUSER is still the operator after a restart" \
                || fail "the operator grant did not survive the restart: $OUT"

# ---------------------------------------------------------------------------
step "10. set-operator on an unknown user fails cleanly"
OUT="$(on "$A" "ray set-operator nosuchuser-e2e" 2>&1)"; rc=$?
echo "$OUT" | strip | sed 's/^/   a| /'
[[ $rc -ne 0 ]] && pass "an unknown user exits non-zero" || fail "an unknown user exited 0"
echo "$OUT" | grep -qi "unknown user" \
  && pass "the error names the unknown user" \
  || fail "unhelpful error for an unknown user: $OUT"
OUT="$(as "$A" "$OPUSER" "ray config get mdns")"
[[ -n "$OUT" ]] && pass "the failed grant left the existing operator alone" \
                || fail "the failed grant disturbed the daemon"

# ---------------------------------------------------------------------------
step "11. ray report is an open read, and the bundle it hands back stays private"
OUT="$(as "$A" "$NOUSER" "ray report")"; rc=$?
echo "$OUT" | strip | sed 's/^/   mallory| /' | head -4
BUNDLE="$(echo "$OUT" | strip | grep -oE '/[^ ]+\.tgz' | head -1)"
if [[ $rc -eq 0 && -n "$BUNDLE" ]]; then
  pass "$NOUSER can collect a diagnostic bundle ($BUNDLE)"
  MODE="$(on "$A" "stat -c %a $BUNDLE" | tr -d '[:space:]')"
  OWNER="$(on "$A" "stat -c %U $BUNDLE" | tr -d '[:space:]')"
  [[ "$MODE" == "600" ]] && pass "the bundle is 0600 (not readable by other local users)" \
                         || fail "the bundle is mode $MODE — the root daemon's logs are world-readable"
  [[ "$OWNER" == "$NOUSER" ]] && pass "the bundle is owned by the requester ($OWNER)" \
                              || fail "the bundle is owned by $OWNER, not the requester"
  on "$A" "rm -f $BUNDLE" >/dev/null 2>&1
else
  fail "$NOUSER could not run 'ray report' (rc=$rc)"
fi

# ---------------------------------------------------------------------------
summary
