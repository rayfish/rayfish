# Rayfish

A peer-to-peer mesh VPN with zero infrastructure. Create a private network, share a code, and your machines reach each other as if they were on the same LAN. No servers to run, no ports to forward, no static IPs to manage.

```bash
ray create                 # you're now the coordinator of a private network
ray invite gaming          # mint a one-time code to hand out
ray join <invite-code>     # a friend joins with the code
ping alice.gaming.ray      # reach each other by name
```

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL%202.0-brightgreen.svg)](LICENSE)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)

---

## Why Rayfish

- **No infrastructure.** There's no control server to host or trust. Peers find each other through a DHT and connect directly. The only "server" is whoever ran `ray create`, and they can be offline once everyone's admitted.
- **Identity, not IP.** Every machine has a cryptographic identity, and its addresses are derived from that identity: stable, collision-free, and assigned without any coordinator handing them out.
- **Private by default.** Networks are closed unless you say otherwise. The code you share to discover a network isn't enough to join it.
- **Works over NAT.** Hole-punching and end-to-end encryption come from [iroh](https://iroh.computer), including automatic port mapping (UPnP/NAT-PMP/PCP). When a direct path isn't possible (roughly 10% of the time), traffic falls back to encrypted relays. For routers that block automatic port mapping, the daemon listens on a fixed UDP port (41383) you can manually forward to guarantee a direct path. A manual forward maps the port to one machine, so only one node per LAN benefits; the others still use automatic traversal and relay fallback.
- **Reach peers by name.** Magic DNS gives you `name.network.ray` so you never memorize a virtual IP.

## How it works

Each machine runs a small daemon (comparable to Tailscale's `tailscaled`) that creates a TUN device, captures IP packets, and tunnels them over iroh's QUIC connections. Everything else (`create`, `join`, `status`, file sharing) is an unprivileged command that talks to the daemon over a local socket.

1. **Create.** One peer starts a network and becomes its coordinator. The network's public key is its **room id**: it lets others discover the network but, on a closed network, is not enough to get in.
2. **Join.** On a closed network a peer gets in with a one-time invite code (`ray invite`) or by requesting approval (`ray requests` / `ray accept`). The coordinator is the gatekeeper.
3. **Mesh.** Every peer derives its own stable virtual IPv4 (`100.64.0.0/10`) and IPv6 (`200::/7`) from its identity, then connects directly to every other peer.
4. **Use it.** Any TCP/UDP app works, addressed by IP or by `name.network.ray`.

## Features

- 🔒 **Closed-by-default networks** with one-time invites, reusable fleet keys, or live approval (`--open` for public ones)
- 🤝 **Direct 2-peer connections.** `ray connect <contact-id>` links you to one person with no room id or invite, approved like a friend request
- 🌐 **Magic DNS.** `name.network.ray`, updated live as peers join, leave, or rename
- 🧱 **Per-device firewall.** Directional, per-port, per-network rules with stateful return traffic. Secure by default: out of the box, unsolicited inbound TCP/UDP is denied (no local service port is exposed when you join a public network), while inbound ICMP (ping) and all outbound traffic are allowed. `ray firewall add in allow -p tcp --port N` opens a port (`--port` also takes a range `80-443` or a comma list `80,443`); `ray firewall default allow` restores permissive inbound behavior. By default a denied packet is silently dropped (stealthy); `ray firewall reject on` switches to "fail fast" mode, replying with a TCP RST / ICMP-unreachable so a blocked connection fails immediately ("connection refused") instead of hanging.
- 🔑 **Mesh SSH, no keys.** `ray firewall ssh on` runs an embedded SSH server on your mesh IPs; `ray firewall ssh allow <network> <peer>` authorizes a peer to log in. Connect with a stock client (`ssh user@host.ray`) — the peer is authenticated by its mesh identity, so there are no `authorized_keys` to distribute (Tailscale-style). For now an authorized peer may log in as any local user.
- 🤝 **Coordinator firewall suggestions.** On any network the coordinator can suggest firewall rules that ride the signed network record (`*` targets all hosts); each node reviews them or opts into auto-install with `--auto-accept-firewall`.
- 📜 **Declarative provisioning.** `ray apply deploy.yaml` stands up networks and firewall rules from a YAML spec. Define `aliases:` (a name for a user, expanding to all their devices) and `groups:` (a set of users/hosts) once, then reference them in firewall rules instead of repeating hostnames. `ray identityof <net> <host>` prints the identity string to alias.
- 👥 **Multi-device identity.** Pair your laptop and phone under one identity; encrypted key backup (optionally to 1Password).
- 📁 **File sharing.** `ray send file.zip bob`.
- 📡 **mDNS** local discovery, and optional **Tor** transport.
- 🛠 **Operator model.** Like Tailscale, run day-to-day commands without `sudo`.

## Quick start

### 1. Install & start

```bash
cargo build
sudo ray up    # installs the system service if needed, then activates the VPN
```

The first `ray up` needs root: it installs the system service and starts the daemon, which owns the TUN device and the iroh endpoint. After that the daemon stays running and every command, including `ray up`/`ray down`, runs unprivileged over a local socket. `ray down` is standby: it takes only the data plane offline (TUN, DNS) while keeping peer connections alive, so `ray up` is near-instant. To stop the daemon entirely (fully offline, connections closed), use `sudo ray stop`; `sudo ray start` brings it back.

#### Updating

```bash
ray --version            # show the installed version + git sha (also `ray version`)
ray update --check       # report current vs the latest GitHub release
ray update --list        # list available releases (newest first)
sudo ray update          # download + verify the latest stable release, swap the binary, restart the daemon
sudo ray update --nightly        # track the rolling nightly (rebuilt on every commit to master)
sudo ray update --version 0.1.0  # install a specific release (downgrades allowed)
```

`ray update` fetches a release from GitHub, verifies its SHA-256, atomically replaces the running `ray` binary, and (if the system service is installed) restarts the daemon onto the new version. By default it tracks the latest stable release; `--nightly` follows the rolling pre-release built from every commit, and `--version X` pins a specific release. There is no persisted channel: each run picks its target from the flag. It needs root when the installed binary lives in a system path (so use `sudo ray update`); `ray --version`, `ray update --check`, and `ray update --list` do not.

### 2. Create a network

```bash
ray create --hostname alice          # closed by default; add --open for a public network
# ✓ network created  gentle-amber-fox
#   IPv4  100.64.23.142
#   IPv6  200:ab3f:d92c:1e4a::1
```

### 3. Invite someone

```bash
ray invite gentle-amber-fox          # mint a single-use, expiring code
# ✓ invite ab3f9c01
#   <invite-code>
#   single-use, expires in 7d
```

Hand the code to a friend. On a closed network they can also run `ray join <room-id>` to land in your approval queue (see [Who can join](#who-can-join)).

### 4. Join from another machine

```bash
ray join <invite-code> --name gaming --hostname bob
# ✓ joined gaming
#   IPv4  100.64.7.201
#   IPv6  200:7c10:5e8b:33a1::1
```

### 5. Reach each other

```bash
ray status               # networks, peers, and traffic
ping alice.gaming.ray    # by name
ping bob.ray             # flat lookup
ping 100.64.23.142       # or just the IP
ray ping alice           # mesh probe: RTT, loss, and direct-vs-relay path
ray netcheck             # your own bound port, relay, and reachability
```

`ray ping` is a mesh-aware probe: it sends live echo probes over the encrypted
connection and reports per-probe latency, packet loss, and whether traffic is
flowing **direct** (hole-punched) or via a **relay**, so you can tell at a glance
why a link is slow. `ray netcheck` reports your own node's conditions: the bound
UDP port (and whether it is the fixed, forwardable port), your home relay and its
latency, your public addresses, and whether UDP is getting through.

### 6. Leave or pause

```bash
ray leave gaming         # leave a network
ray kick gaming alice    # coordinator only: remove a member from a closed network (disconnects them mesh-wide)
ray down                 # standby: data plane (TUN + DNS) off, still connected to peers
ray up                   # reactivate (no root needed, near-instant: connections were kept)
sudo ray stop            # fully offline: daemon exits, peer connections close
sudo ray start           # back online: daemon restarts with both planes on
```

Run `ray --help` to discover the rest: `invite`, `requests`/`accept`/`deny`, `firewall`, `apply`, `send`, `pair`, `mdns`, and more.

## Who can join

The **room id** (a network's public key) is a discovery key. It's published so peers can find the network, but on a closed network it is not an admission credential. Admission is always the coordinator's job:

- **Closed (default)** has three ways in:
  - **Invite code.** `ray invite <network>` mints a single-use, expiring code. The holder runs `ray join <code>`; the coordinator verifies and burns it. Manage with `ray invite <network> list` / `revoke <id>`.
  - **Reusable key.** `ray invite <network> --reusable` mints a multi-use, expiring key for unattended fleets. Its hash rides the network's signed record, so it admits many machines and `revoke` propagates to every key-holder. A server joins non-interactively with `ray join <key> --hostname web --auto-accept-firewall`. The name isn't authoritative, so two servers asking for `web` become `web` and `web-1`. For stable per-host names give each a unique `--hostname` (e.g. a cloud instance id), and prefer the `*` wildcard subject for fleet firewall suggestions (a rule keyed to one hostname can retarget as servers come and go). Key expiry is not member expiry: expiry/revoke only blocks new joins; machines already admitted stay members.
  - **Live approval.** The holder of just the room id runs `ray join <room-id>` and lands in a queue. The coordinator runs `ray requests <network>`, then `ray accept <network> <id>` (or `ray deny`).
- **Open** (`ray create --open`) lets anyone with the room id join directly. Good for public or community networks.

Either gate runs through a coordinator. The full coordinator set is published in the network's signed record (`Member.is_coordinator`), so a fresh joiner dials the invite minter first, then falls back across the other coordinators. Admission survives any one coordinator being offline. Once admitted, a member reconnects by cryptographic identity and no coordinator needs to be online.

### Direct 2-peer connections

To link up with one person, skip room ids and invite codes entirely. Everyone has a standing **contact id** (`ray contact id`, also shown at the top of `ray status`): a rotatable handle, separate from your network identity, that you can share like a phone number.

```bash
ray connect <their-contact-id>     # ask to connect; you wait, pending
ray connections                    # they see the request…
ray connections approve <id>       # …and approve it
```

Approval creates a private **2-peer network** automatically (shown as `[direct]` in `ray status`). It's a real network, so firewall rules, Magic DNS, and the mesh all work the same. Approval is recipient-only: the requester consents by asking, the recipient consents by approving. Rotate your contact id anytime with `ray contact rotate` to stop new requests (existing links keep working). To stay unreachable, don't share the id.

## Permissions

Like Tailscale, the daemon authorizes each command by the **caller's UID**, not by file permissions:

- Read-only commands (`status`, `*… show`, `files`) are open to any local user.
- Mutating commands need root or the configured operator.
- The user who installs the service (`sudo ray up` / `ray install`) becomes the operator automatically, so they keep working without `sudo`. Authorize someone else with `sudo ray set-operator <user>`.

Only a handful of commands need root, because they manage the system service itself:

```bash
sudo ray install | restart | uninstall   # manage the service unit / launchd plist
sudo ray start | stop                    # start / stop the service. stop = fully offline (closes peer connections); start = back online
sudo ray set-operator <user>              # let a user run ray without sudo
```

## Custom relay & DNS

By default rayfish uses iroh's public infrastructure for relay fallback and peer
discovery. You can point it at your own servers (or the rayfish-operated ones)
with `ray config`:

```bash
ray config                                   # show current settings
ray config set relay rayfish                 # use the rayfish relay (keeps n0 as fallback)
ray config set relay https://r1,https://r2   # multiple custom relays
ray config set discovery-dns rayfish         # custom discovery / pkarr server
ray config set dns-upstreams 1.1.1.1,8.8.8.8 # forwarders for non-.ray names
ray config set relay https://r1 --replace    # drop the n0 defaults entirely
ray config unset relay                        # back to defaults
```

Keys: `relay`, `discovery-dns`, `dns-upstreams`. Values are a comma list of
presets (`rayfish`, `n0`), URLs, or IPv4 addresses. By default custom servers are
added alongside the defaults; `--replace` swaps them out (a bad custom server
with no fallback can isolate the node). Settings are saved to `settings.toml` and
take effect on `sudo ray restart`.

## Troubleshooting

```bash
ray report               # bundle logs + metrics, open a pre-filled GitHub issue
```

The daemon writes rolling logs to `/var/log/rayfish/` (Linux) or `/Library/Logs/rayfish/` (macOS). `ray report` collects those logs, current metrics, and a **sanitized** status snapshot (no private keys) into a `.tgz`, then opens a pre-filled GitHub issue for you to attach. The bundle is written locally first, so you can review it before sharing.

## How it compares

Rayfish sits closest to [Tailscale](https://tailscale.com), but without a coordination server: there's no account, no control plane, and nothing to self-host. The network's signed record on a public DHT is the only shared state. Unlike raw [WireGuard](https://www.wireguard.com), you don't hand-manage keys, IPs, or peer configs. Unlike [Nebula](https://github.com/slackhq/nebula), there's no certificate authority to run; identity is the key.

## Status

Rayfish is experimental, pre-1.0 software and has not had an independent security audit. The wire format and on-disk config may still change between releases. Please [file issues](https://github.com/rayfish/rayfish/issues), but don't rely on it for anything critical yet.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full history, or the [releases page](https://github.com/rayfish/rayfish/releases) for per-version notes. `ray update --list` shows available releases and `ray update --check` reports what a pending upgrade brings.

## Building

```bash
cargo build                  # debug build
cargo build --features tor   # optional Tor transport
cargo build --features otel  # optional OTLP span export
```

Requires the Rust 2024 edition (Rust 1.85+).

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) to report vulnerabilities privately.

## License

Rayfish is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0).
