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
  local user="${4:-root}" port="${5:-22}"
  on "$from" "ssh -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
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

A_IP="$(my_ip "$A" "$NET")"; B_IP="$(my_ip "$B" "$NET")"
echo "   A mesh ip=$A_IP  B mesh ip=$B_IP"
[[ -n "$A_IP" && -n "$B_IP" ]] || { fail "missing mesh IP(s)"; summary; }
pass "both have a mesh IP"
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
step "5f. forwards run with the login account's rights, not the daemon's"
# The daemon is root. A forward it opened or bound as root would hand a
# non-root login root's view of the host: SO_PEERCRED uid 0 at the ray IPC
# socket, root-only sockets, privileged ports, and root's own mesh SSH login.
DEPLOY_UID="$(on "$A" 'id -u deploy')"
SSH_BASE="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
  -o ConnectTimeout=8 -o PreferredAuthentications=none,publickey"
# Probe servers on srv-a: one reports the connecting uid, one sits in a
# directory only root can enter.
# `on` gives the remote no stdin, so the script travels base64 in the command.
PROBE="$(base64 -w0 <<'PY'
import os, socket, struct, sys, threading
def serve(path, reply):
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    os.chmod(path, 0o777)
    s.listen(8)
    while True:
        c, _ = s.accept()
        cred = c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        c.sendall(reply(struct.unpack("3i", cred)[1]).encode())
        c.close()
threading.Thread(target=serve, args=("/tmp/e2e-fwd/peercred.sock",
    lambda uid: "uid=%d\n" % uid), daemon=True).start()
serve("/root/e2e-fwd/secret.sock", lambda uid: "root-secret\n")
PY
)"
on "$A" "rm -rf /tmp/e2e-fwd /root/e2e-fwd && mkdir -p /tmp/e2e-fwd /root/e2e-fwd \
  && chmod 1777 /tmp/e2e-fwd && chmod 700 /root/e2e-fwd \
  && echo $PROBE | base64 -d > /root/e2e-probe.py"
on "$A" 'nohup python3 /root/e2e-probe.py >/dev/null 2>&1 &' >/dev/null
retry_until 15 "on '$A' 'test -S /root/e2e-fwd/secret.sock'" >/dev/null \
  || fail "probe sockets did not come up on srv-a"

# Open `-L <lport>:<target>` from srv-b as <user>, read what the target says,
# then drop the tunnel. `-E` doubles as a marker for pkill; the bracket keeps
# the pattern from matching the remote shell that runs pkill.
fwd_read(){ # <lport> <target> <user> [ssh-port]
  local lport="$1" target="$2" user="$3" port="${4:-22}"
  on "$B" "ssh -p $port $SSH_BASE -E /tmp/e2e-fwd-$lport.log -f -N \
      -L 127.0.0.1:$lport:$target $user@$A_IP 2>&1 \
    && python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\",$lport),5); \
      s.settimeout(5); print(s.recv(100).decode().strip())' 2>&1; \
    pkill -f '/tmp/e2e-fw[d]-$lport.log' || true"
}

OUT="$(fwd_read 15001 /tmp/e2e-fwd/peercred.sock deploy)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qx "uid=$DEPLOY_UID" \
  && pass "a forwarded unix socket sees the login uid ($DEPLOY_UID), not the daemon's" \
  || fail "forwarded socket peer was not deploy (want uid=$DEPLOY_UID): $OUT"

OUT="$(fwd_read 15002 /root/e2e-fwd/secret.sock deploy)"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -q root-secret \
  && fail "non-root login reached a root-only socket through -L" \
  || pass "non-root login cannot forward to a root-only socket"

OUT="$(on "$B" "ssh $SSH_BASE -E /tmp/e2e-fwd-rev.log -o ExitOnForwardFailure=yes -f -N \
    -R /tmp/e2e-fwd/rev.sock:127.0.0.1:22 deploy@$A_IP 2>&1 && echo started")"
OWNER="$(on "$A" 'stat -c %U /tmp/e2e-fwd/rev.sock 2>&1')"
on "$B" "pkill -f '/tmp/e2e-fw[d]-rev.log' || true"
echo "   a| reverse socket owner: $OWNER"
[[ "$OWNER" == deploy ]] \
  && pass "a reverse-forwarded socket is bound as the login account" \
  || fail "reverse-forwarded socket owner is '$OWNER', want deploy ($OUT)"

OUT="$(on "$B" "timeout 20 ssh $SSH_BASE -o ExitOnForwardFailure=yes -N \
    -R 127.0.0.1:81:127.0.0.1:22 deploy@$A_IP 2>&1; echo rc=\$?")"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi 'forwarding failed' \
  && pass "non-root login cannot bind a privileged port with -R" \
  || fail "privileged -R port was not refused for deploy: $OUT"

# `timeout`: a client left waiting on an agent channel must fail, not hang.
OUT="$(on "$B" "eval \$(ssh-agent -s) >/dev/null; timeout 20 ssh $SSH_BASE -A deploy@$A_IP \
    'stat -c %U \"\$SSH_AUTH_SOCK\"; ssh-add -l >/dev/null 2>&1; echo agent-rc=\$?' 2>&1; \
    echo ssh-rc=\$?; ssh-agent -k >/dev/null")"
echo "$OUT" | sed 's/^/   b| /'
# ssh-add exits 1 for an empty agent it reached and 2 when it reached nothing.
echo "$OUT" | grep -qx deploy && echo "$OUT" | grep -qx 'agent-rc=1' \
  && pass "agent socket is owned by the login account and reaches the agent" \
  || fail "agent forwarding: want owner deploy and agent-rc=1: $OUT"
echo "$OUT" | grep -qx 'ssh-rc=0' \
  && pass "the client exits once its agent connection closes" \
  || fail "ssh -A did not exit after the agent connection closed: $OUT"

# A -L into this host's own mesh SSH port is dialed by the daemon. Taking that
# connection for self-SSH would trust the daemon's socket and log in as root.
on "$A" 'ray config set ssh-port 2222' >/dev/null
SINCE="$(on "$A" 'date +%s')"
OUT="$(on "$B" "ssh -p 2222 $SSH_BASE -E /tmp/e2e-fwd-self.log -f -N \
    -L 127.0.0.1:15003:[$A_IP]:2222 deploy@$A_IP 2>&1; \
    ssh -p 15003 $SSH_BASE root@127.0.0.1 whoami 2>&1; \
    pkill -f '/tmp/e2e-fw[d]-self.log' || true")"
REFUSED="$(on "$A" "journalctl -u rayfish --since @$SINCE --no-pager \
  | grep -c 'self-SSH from a socket the daemon holds'")"
on "$A" 'ray config set ssh-port 22' >/dev/null
echo "$OUT" | sed 's/^/   b| /'
# The daemon drops the connection before the handshake, so the client sees a
# closed connection; the log line is what shows the tunnel got that far.
if echo "$OUT" | grep -qx root; then
  fail "a -L into srv-a's own SSH port logged in as root"
elif [[ "${REFUSED:-0}" -ge 1 ]]; then
  pass "a -L into the host's own SSH port is refused, not taken as root"
else
  fail "the self-SSH tunnel never reached the self listener: $OUT"
fi

on "$A" "pkill -f '/root/e2e-prob[e].py'; rm -rf /tmp/e2e-fwd /root/e2e-fwd /root/e2e-probe.py" || true

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
step "7b. self-SSH follows the local socket owner, even with wildcard mesh grants"
# An IPv6 host sshd may own port 22; exercise the configured mesh listener.
on "$A" 'ray config set ssh-port 2222' >/dev/null
OUT="$(ssh_try "$A" "$A_IP" whoami root 2222)"
echo "$OUT" | grep -qx root && pass "root can SSH to its own mesh address" \
  || fail "root self-SSH failed: $OUT"
for user in meshtest root deploy; do
  OUT="$(on "$A" "runuser -u meshtest -- ssh -p 2222 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8 \
    -o PreferredAuthentications=none $user@$A_IP whoami 2>&1 || true")"
  if [[ "$user" == meshtest ]]; then
    echo "$OUT" | grep -qx meshtest && pass "local user can self-SSH as itself" \
      || fail "local user self-SSH failed: $OUT"
  else
    echo "$OUT" | grep -qiE 'permission denied|authentication fail' \
      && pass "local user cannot self-SSH as $user" \
      || fail "local user self-SSH should deny $user: $OUT"
  fi
done

step "7c. changing the SSH port moves the self listener"
on "$A" 'ray config set ssh-port 2223' >/dev/null
OUT="$(on "$A" "ssh -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o ConnectTimeout=8 -o PreferredAuthentications=none \
  root@$A_IP whoami 2>&1 || true")"
echo "$OUT" | grep -qx root && pass "self-SSH works on the configured port" \
  || fail "self-SSH on changed port failed: $OUT"
on "$A" 'ray config set ssh-port 22' >/dev/null

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
