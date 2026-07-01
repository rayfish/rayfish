#!/usr/bin/env bash
# Mesh SSH (`ray firewall ssh`) e2e test orchestrator.
#
# Topology:
#   srv-a  coordinator of a closed network `ssh`; the SSH *server*
#   srv-b  member; the SSH *client* (a stock OpenSSH client)
#
# Proves the full Tailscale-style mesh SSH flow over real hosts (each of which
# already runs a host sshd on 0.0.0.0:22, so this also exercises the
# coexistence of our mesh-IP:22 listener with the host daemon):
#   off-by-default -> port 22 blocked  ->  `ssh on` opens it but rejects an
#   unauthorized peer at auth  ->  `ssh allow` admits srv-b (whoami == root)
#   ->  `ssh deny` rejects again  ->  `*` wildcard admits  ->  `ssh off` closes
#   the port.
#
# Reads tests/e2e/ssh/.servers (written by provision.sh). Re-runnable.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

NET=ssh

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run $DIR/provision.sh first"; exit 1; }
A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
[[ -n "$A" && -n "$B" ]] || { echo "missing srv-a/srv-b in $SERVERS"; exit 1; }

# Run a stock ssh client on <from> targeting <dst>:22 and echo the combined
# output. none-auth is preferred so an unauthorized peer fails fast at auth
# rather than prompting; BatchMode/ConnectTimeout keep a blocked port from
# hanging the test.
ssh_try(){ # <from-ip> <dst-mesh-ip> <remote-cmd>
  local from="$1" dst="$2" cmd="$3"
  local user="${4:-root}"
  on "$from" "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o ConnectTimeout=8 -o PreferredAuthentications=none,publickey \
    $user@$dst $cmd 2>&1 || true"
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

SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"
A_IP="$(own_ip "$SA")"; B_IP="$(own_ip "$SB")"
echo "   A mesh ip=$A_IP  B mesh ip=$B_IP"
[[ -n "$A_IP" && -n "$B_IP" ]] && pass "both have a mesh IP" || fail "missing mesh IP(s)"
# Confirm baseline mesh reachability before testing SSH on top of it.
png "$B" "$A_IP" "srv-b -> srv-a ($A_IP) baseline ping"

# ---------------------------------------------------------------------------
step "2. SSH off by default — port 22 is blocked over the mesh"
OUT="$(ssh_try "$B" "$A_IP" whoami)"
echo "$OUT" | sed 's/^/   b| /'
if echo "$OUT" | grep -qiE 'timed out|timeout|refused|No route|closed'; then
  pass "mesh SSH port 22 is closed while ssh is off"
else
  fail "expected a blocked connection while ssh off, got: $OUT"
fi

# ---------------------------------------------------------------------------
step "3. ray firewall ssh on — server starts, tcp:22 passthrough seeded"
on "$A" 'ray firewall ssh on' | strip | sed 's/^/   a| /'
SHOW="$(on "$A" 'ray firewall ssh show' | strip)"
echo "$SHOW" | sed 's/^/   a| /'
echo "$SHOW" | grep -qi 'on' && pass "ssh show reports on" || fail "ssh show did not report on"
on "$A" 'ray firewall show' | strip | grep -Ei '22.*ssh|ssh.*22' \
  && pass "tcp:22 passthrough present (tagged ssh)" \
  || fail "tcp:22 passthrough not found in firewall show"

# ---------------------------------------------------------------------------
step "4. unauthorized peer is rejected at auth (port open, not allowed)"
OUT="$(ssh_try "$B" "$A_IP" whoami)"
echo "$OUT" | sed 's/^/   b| /'
if echo "$OUT" | grep -qiE 'permission denied|authentication fail'; then
  pass "unauthorized srv-b is rejected at SSH auth"
elif echo "$OUT" | grep -qi 'root'; then
  fail "unauthorized srv-b got a shell (should have been denied)"
else
  fail "unexpected output for unauthorized attempt: $OUT"
fi

# ---------------------------------------------------------------------------
step "5. ray firewall ssh allow srv-b — default grants any non-root user only"
# Create a plain user on srv-a; the default allow (no --user) permits non-root
# logins but must NOT permit root.
on "$A" 'id meshtest >/dev/null 2>&1 || useradd -m -s /bin/bash meshtest' >/dev/null 2>&1
on "$A" "ray firewall ssh allow $NET srv-b" | strip | sed 's/^/   a| /'
# root is denied under the default (non-root) policy.
OUT="$(ssh_try "$B" "$A_IP" whoami root)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qiE 'permission denied|authentication fail' \
  && pass "root login denied under the non-root default" \
  || fail "root login should have been denied under the default: $OUT"
# meshtest (non-root) is admitted.
OUT="$(ssh_try "$B" "$A_IP" whoami meshtest)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi '^meshtest' && pass "non-root srv-b logged in (whoami == meshtest)" \
  || fail "non-root srv-b could not log in: $OUT"
# exec path with a distinctive marker.
OUT="$(ssh_try "$B" "$A_IP" 'echo ray-ssh-ok-$((6*7))' meshtest)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -q 'ray-ssh-ok-42' && pass "exec command runs over mesh SSH" \
  || fail "exec command did not run: $OUT"

# ---------------------------------------------------------------------------
step "5b. privilege drop — login as a non-root user sheds the daemon's groups"
# The daemon runs as root (groups include 0/root). A correct privilege drop calls
# initgroups so the spawned shell gets ONLY the target user's groups. `id` for
# meshtest must not show root's group.
IDOUT="$(ssh_try "$B" "$A_IP" id meshtest)"
echo "$IDOUT" | sed 's/^/   b| /'
if echo "$IDOUT" | grep -q 'uid=[0-9]*(meshtest)'; then
  if echo "$IDOUT" | grep -qE '\(root\)|groups=.*\b0\('; then
    fail "login shell leaked the root daemon's supplementary groups: $IDOUT"
  else
    pass "non-root login has only its own groups (no root/0 leaked)"
  fi
else
  fail "could not log in as meshtest: $IDOUT"
fi

# ---------------------------------------------------------------------------
step "5c. piped exec output is untranslated (no PTY CRLF)"
# `ssh host cmd` without -t must use pipes, so a bare LF is NOT turned into CRLF
# (which would corrupt piped/binary output). Count carriage returns in the output
# of a command that prints one newline: pipe path = 0, PTY path = 1.
CR="$(on "$B" "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o ConnectTimeout=8 -o PreferredAuthentications=none,publickey \
  meshtest@$A_IP echo hi 2>/dev/null | tr -cd '\r' | wc -c | tr -d ' '")"
echo "   b| carriage-returns in output: ${CR:-?}"
[[ "${CR:-1}" == "0" ]] && pass "non-PTY exec output is byte-clean (no CRLF translation)" \
  || fail "non-PTY exec output was CRLF-translated (CR count=${CR:-?})"

# ---------------------------------------------------------------------------
step "5d. --user '*' grants root explicitly"
on "$A" "ray firewall ssh allow $NET srv-b --user '*'" | strip | sed 's/^/   a| /'
OUT="$(ssh_try "$B" "$A_IP" whoami root)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi '^root' && pass "root login allowed once '*' is granted" \
  || fail "root login should be allowed with --user '*': $OUT"

# ---------------------------------------------------------------------------
step "5e. --user deploy restricts to a single named account"
# Setting the rule to a single user replaces the prior '*'. Only `deploy` may log
# in: the named user works, but root AND any other non-root user are denied.
on "$A" 'id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy' >/dev/null 2>&1
on "$A" "ray firewall ssh allow $NET srv-b --user deploy" | strip | sed 's/^/   a| /'
# the named user is admitted
OUT="$(ssh_try "$B" "$A_IP" whoami deploy)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi '^deploy' && pass "named user 'deploy' admitted" \
  || fail "named user 'deploy' could not log in: $OUT"
# a different non-root user is denied (the single-user list replaced '*')
OUT="$(ssh_try "$B" "$A_IP" whoami meshtest)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qiE 'permission denied|authentication fail' \
  && pass "other non-root user 'meshtest' denied when restricted to 'deploy'" \
  || fail "meshtest should be denied when only 'deploy' is allowed: $OUT"
# root is denied
OUT="$(ssh_try "$B" "$A_IP" whoami root)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qiE 'permission denied|authentication fail' \
  && pass "root denied when restricted to 'deploy'" \
  || fail "root should be denied when only 'deploy' is allowed: $OUT"

# ---------------------------------------------------------------------------
step "6. ray firewall ssh deny srv-b — access revoked"
on "$A" "ray firewall ssh deny $NET srv-b" | strip | sed 's/^/   a| /'
OUT="$(ssh_try "$B" "$A_IP" whoami meshtest)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qiE 'permission denied|authentication fail' \
  && pass "revoked srv-b is rejected again" \
  || fail "revoked srv-b was not rejected: $OUT"

# ---------------------------------------------------------------------------
step "7. wildcard peer allow (* with --user '*') admits any peer as any user"
on "$A" "ray firewall ssh allow $NET '*' --user '*'" | strip | sed 's/^/   a| /'
OUT="$(ssh_try "$B" "$A_IP" whoami root)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi '^root' && pass "wildcard allow admits srv-b as root" \
  || fail "wildcard allow did not admit srv-b: $OUT"

# ---------------------------------------------------------------------------
step "8. ray firewall ssh off — port closes again"
on "$A" 'ray firewall ssh off' | strip | sed 's/^/   a| /'
on "$A" 'ray firewall show' | strip | grep -Ei '22.*ssh|ssh.*22' \
  && fail "tcp:22 passthrough still present after ssh off" \
  || pass "tcp:22 passthrough removed after ssh off"
OUT="$(ssh_try "$B" "$A_IP" whoami)"
echo "$OUT" | sed 's/^/   b| /'
if echo "$OUT" | grep -qiE 'timed out|timeout|refused|No route|closed'; then
  pass "mesh SSH port 22 closed again after ssh off"
else
  fail "expected a blocked connection after ssh off, got: $OUT"
fi

# ---------------------------------------------------------------------------
summary
