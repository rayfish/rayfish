# e2e node image: a container that behaves enough like a cloud instance for
# the scenario scripts to drive it unchanged — systemd as PID 1, sshd on
# 0.0.0.0:22 with root key login, and the handful of tools the scripts shell out
# to on the remote side.
#
# Ubuntu 22.04 on purpose: it is the glibc floor `just cross` builds against
# (see Cross.toml / cross/Dockerfile.gnu), so the deployed binary runs as-is.
FROM ubuntu:22.04

# systemd/systemd-sysv/dbus: PID 1 and service management, so `ray up`,
#   `systemctl restart rayfish` and the stop/start steps take the real code path.
# openssh-server: the harness dials in; openssh-client: tests/e2e/ssh dials out.
# rsync: `just scp`. python3: the TCP/UDP probes. procps: `pkill`, used to stop
#   those probes (without it, listeners leak between steps).
# iproute2: `ip link` from the daemon, `ss` from the dns scenario.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        openssh-server openssh-client \
        rsync python3 procps iproute2 iputils-ping \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Host keys at build time so they stay stable across container recreation: the
# runner's known_hosts survives a fleet being rebuilt.
# No ttys in a container, and a failed getty leaves systemd degraded.
RUN systemctl mask getty.target console-getty.service

RUN ssh-keygen -A \
    && mkdir -p /root/.ssh /run/sshd \
    && chmod 700 /root/.ssh \
    && printf 'PermitRootLogin prohibit-password\nUseDNS no\n' \
        > /etc/ssh/sshd_config.d/e2e.conf \
    && systemctl enable ssh

# Seed a settings.toml with mDNS off before every daemon start. All the nodes
# share one bridge, so mDNS would give peers a discovery shortcut no real fleet
# has. A drop-in survives the daemon rewriting its own unit on install, and the
# `-` prefix keeps a failure here from aborting a unit that never retries.
# `reset_state` wipes /etc/rayfish between runs, which is why this re-runs on
# every start rather than being baked into the image.
RUN mkdir -p /etc/systemd/system/rayfish.service.d
COPY e2e-seed.conf /etc/systemd/system/rayfish.service.d/e2e.conf

CMD ["/sbin/init"]
