# Rayfish end-to-end tests

Each scenario provisions a fleet of hosts, deploys `ray` over SSH, drives a flow end
to end, and prints a `PASS`/`FAIL` line per check (exit non-zero on any failure). The
shared SSH/deploy/reset/assert plumbing lives in [`../lib/`](../lib) and is sourced by
every scenario.

A host is anything that answers `ssh root@<ip>`, so there are two backends: real
DigitalOcean droplets (the default) and local Docker containers
(`E2E_BACKEND=docker`). See [Backends](#backends).

## Scenarios

| Dir | Hosts | What it proves |
|-----|-------|----------------|
| [`device-cert/`](device-cert) | 3 | A third peer reaches a user identity backed by two paired devices (`ray pair` + DeviceCert), over a closed (invite-gated) network. |
| [`connect/`](connect) | 2 | The `ray connect` direct 2-peer friend-request flow over the public pkarr DHT — request, approve, `[direct]` network, ping + `ray send`, per-network firewall, offline negative case. |
| [`firewall/`](firewall) | 3 | The coordinator suggested-firewall pipeline (`suggest` → `pending`/`accept`, `auto-accept`, additive whitelist vs blacklist) and the per-packet rule matrix (UDP, port ranges, same-selector replace, `--network` scoping) over a real TUN. |
| [`closed-net/`](closed-net) | 3 | Closed-net admission + lifecycle commands: live approval (`requests`/`accept`/`deny`), co-coordinator (`admin add`) gatekeeper resilience with a reusable key, `ray hostname` + magic-DNS, `ray leave`/`nuke`, and a `ray apply` smoke. |
| [`apply/`](apply) | 3 | Declarative `ray apply` deploy end to end: create-if-absent + membership-gap diff, `--invite-missing`, `ray identityof`, alias/group expansion (`--dry-run`), real suggestion publish + data-plane enforcement, and `--prune`. |
| [`dns/`](dns) | 2 | Magic DNS resolution over a real TUN: `<host>.<net>.ray` resolves via the system resolver, drives reachability, no host `:53` bind, non-`.ray` passthrough, and `ray down` revert. |
| [`ssh/`](ssh) | 2 | Mesh SSH (`ray firewall ssh`): the allow/deny matrix over the TUN, so an SSH grant is a firewall rule and not a separate door. |
| [`operator/`](operator) | 2 | Unprivileged-client authority (`ray set-operator`): reads open to any local user, mutations denied with the fix named, the grant root-only, one UID, non-transferable, and live on the packet path once given. |
| [`v4bridge/`](v4bridge) | 2 | A service listening on `0.0.0.0` answers over the IPv6-only mesh: the payload path by IP and by `.ray` name, the firewall still upstream of the bridge, loopback-only services declined, no bind/unbind flap across rescans, the setting + data-plane lifetime, and a new listener picked up from a kernel event rather than a timer (droplets only, see the scenario README). |
| [`reliability/`](reliability) | 4 | Full-mesh packet-loss test: every pair probed both ways with `ping -c 1000 -i 0.01`, ICMP flood, and iperf3 UDP, over the rayfish tunnel vs the direct public-IP baseline. Fails when rayfish adds loss over the raw link. |
| [`restore-offline/`](restore-offline) | 3 | A member whose daemon restarts while its coordinator is offline keeps the network and re-meshes with the *other* member, rather than dropping the network until the coordinator returns. |
| [`unpair/`](unpair) | 3 | `ray unpair` revokes a device cert: the nullifier rides the signed blob, a third peer drops the unpaired device, and the device cannot re-join. |
| [`churn/`](churn) | 4 | Lifecycle events under churn: repeated hard flap, simultaneous flap, `ray down`/`up` cycles (including one on a host with no `ip` binary, since link state goes over netlink), and a `kick`/`nuke` delivered while a member is offline (which must still converge from the signed blob). Ends with a no-panic/no-crash-restart sweep. |
| [`exit-node/`](exit-node) | 3 | The internet-gateway path: `allow`/`use` forwarding + NAT, full-tunnel egress, `SO_MARK` loop prevention, the IPv6-only tunnel gate, and the deny path. |

Everything runs through one dispatcher, [`../e2e.sh`](../e2e.sh):

```bash
tests/e2e.sh <scenario>             # provision (if needed) + deploy + drive + assert
tests/e2e.sh <scenario> provision   # just spin up instances -> <dir>/.servers
tests/e2e.sh <scenario> teardown    # destroy the instances (manual)
```

where `<scenario>` is `device-cert`, `connect`, `firewall`, `closed-net`,
`apply`, `dns`, `ssh`, `operator`, `v4bridge`, `reliability`, `restore-offline`,
`unpair`, `churn`, `exit-node`, `all`, or `bench` (run `tests/e2e.sh` with no scenario for usage). The per-scenario run steps live in `<dir>/run.sh`
(still runnable directly once `.servers` exists); the fleet definitions and the
provision/teardown/assert bodies are shared in [`../lib/`](../lib).

The throughput/latency benchmark (`tests/e2e.sh bench`) is a sibling suite
under [`../bench/`](../bench) (same shared `tests/lib/`).

## Prerequisites (both backends)

- `jq` (the assertions parse `ray status --json` on the runner), plus `just` and
  `cross` with Docker running (the x86_64-linux build behind `just deploy`).
- An SSH keypair at one of `~/.ssh/id_*`. Leave `SSH_KEY` at its default: `just scp`
  runs bare `rsync`/`ssh` with no `-i`, so the hosts have to accept ssh's default
  identity.

## Backends

`E2E_BACKEND` selects one; the `.servers` region column records which backend wrote
a fleet, and each backend refuses to touch the other's.

### `digitalocean` (default)

Real droplets, one fleet per scenario. Needs `doctl` authenticated (`doctl auth
init`, then `doctl account get` should work) and at least one SSH key on the
account.

Droplets are created with `--enable-ipv6`, which matters more than it looks:
the overlay is IPv6-only and `exit-node/run.sh` **skips** its egress assertions
on a host with no v6 internet, so a fleet without IPv6 makes that suite pass
without testing the tunnel. IPv6 is settable only at create time, so a fleet
provisioned without it is easier to destroy and recreate than to fix. Provision
warns when a droplet comes up without a v6 address.

Unlike some providers, DigitalOcean injects **no** SSH key unless `--ssh-keys`
names one, so the provisioner passes every key on the account by default
(`DO_SSH_KEYS` overrides with a comma-separated list of ids or fingerprints).
That matches what the harness needs: `just scp` runs bare `rsync`/`ssh` with no
`-i`, so the hosts have to accept ssh's default identity.

### `docker`

```bash
E2E_BACKEND=docker tests/e2e.sh <scenario>
```

Each host is a container from [`../docker/`](../docker): Ubuntu 22.04 (the glibc floor
`just cross` builds against) running systemd as PID 1, with sshd on `0.0.0.0:22`. They
share one bridge and reach the internet through the host's NAT, which the daemon needs
for pkarr and the relays. Also needs `/dev/net/tun` on the host; the containers run
`--privileged`, because systemd manages its own cgroups.

The fleet is recreated on every `run`. `device-cert` and `unpair` never call `ray up`
after deploying, so a redeployed-but-not-reactivated daemon comes back in standby and
every data-plane check fails; containers are cheap enough to just rebuild.
`E2E_DOCKER_REUSE=1` keeps a live fleet if you want to poke at it.

**Cloud-only scenarios.** `exit-node`, `reliability` and `bench` exit early under
this backend. All the containers share the host's public IP, and `exit-node` asserts
the opposite by design ("srv-a and srv-b already share a public IP: the egress
assertion would be meaningless"); `reliability` and `bench` measure the rayfish path
against a direct-public-IP baseline that on one host is the same bridge.

**What a green docker run does not cover:**

- No NAT between peers, so no hole punching and no relay fallback anywhere.
- The bridge is a `fd00:e2e::/64` ULA with no v6 egress, so anything that probes
  the IPv6 internet has nothing to reach.
- The nodes take the direct `/etc/resolv.conf` DNS path; DigitalOcean's
  `ubuntu-22-04-x64` runs systemd-resolved and takes the D-Bus path. The conditional
  takeover block in `dns/run.sh` is skipped on droplets and exercised here:
  complementary, not equal.
- `dns/run.sh`'s "no host `:53` bind" check has no positive control in a container
  with no `:53` listener at all, so it passes for free.
- tracefs is masked in the node image, so `v4bridge/run.sh` step 12 exercises
  the timer fallback and never the kernel listen events the daemon actually uses
  on Linux (`src/listen_events.rs`). It says so when it runs. The masking is not
  incidental: tracefs is not namespaced, so every container shares the host
  kernel's single `/sys/kernel/tracing`, and each node's daemon would open the
  same trace instance and read the same *consuming* `trace_pipe`, so one node's
  listen event gets delivered to another node's daemon. Left mounted, that path works
  or does not by fleet-size accident (see `../docker/Dockerfile`).
- mDNS is off on the nodes (one bridge means every node hears every other one, which
  no real fleet does). `E2E_DOCKER_MDNS=1` turns it back on.

## Common environment overrides

| Var | Default | Meaning |
|-----|---------|---------|
| `E2E_BACKEND` | `digitalocean` | `digitalocean` or `docker` |
| `REGION` | `fra1` | droplet region (provision) |
| `SIZE` | `s-1vcpu-1gb` | droplet size slug (provision) |
| `IMAGE` | `ubuntu-22-04-x64` | droplet image slug (provision) |
| `DO_SSH_KEYS` | every key on the account | comma-separated key ids/fingerprints (provision) |
| `SSH_KEY` | `~/.ssh/id_ed25519` | private key for `root@<ip>` |
| `KEEP_STATE` | `0` | `1` skips the per-run rayfish state wipe |
| `E2E_DOCKER_REUSE` | `0` | `1` keeps a live container fleet instead of recreating it |
| `E2E_DOCKER_REBUILD` | `0` | `1` rebuilds the node image |
| `E2E_DOCKER_MDNS` | `0` | `1` leaves mDNS enabled on the nodes |
| `E2E_DOCKER_IMAGE` / `_NET` / `_SUBNET` / `_SUBNET6` | see `lib/docker.sh` | names the backend uses |
