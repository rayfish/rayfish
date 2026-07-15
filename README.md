# Rayfish

**Your machines, on one private network, anywhere.** Rayfish is a peer-to-peer
mesh VPN that lets your laptop, phone, server, and your friends' machines talk
to each other as if they were all plugged into the same router, even when
they're scattered across the world behind different NATs.

There's nothing to host and nothing to sign up for. You don't rent a server,
open a port, or hand out IP addresses. One person runs a command, shares a code,
and the network exists.

```bash
ray create                 # you now have a private network of your own
ray invite gaming          # mint a one-time code to hand out
ray join <invite-code>     # a friend joins with the code
ping alice.gaming.ray      # you reach each other by name
```

That's the whole idea. The rest of this README is the details.

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL%202.0-brightgreen.svg)](LICENSE)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)

**Jump to:** [Why](#why-rayfish) · [How it works](#how-it-works) · [Features](#features) · [Quick start](#quick-start) · [Managing your network](#managing-your-network) · [Who can join](#who-can-join) · [Firewall](#firewall) · [Provisioning](#declarative-provisioning) · [Permissions](#permissions) · [Custom relay & DNS](#custom-relay--dns) · [Troubleshooting](#troubleshooting) · [How it compares](#how-it-compares) · [FAQ](#faq)

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

Each of these has a fuller treatment further down; this is the one-line tour.

- 🔒 **Closed-by-default networks.** One-time invites, reusable fleet keys, or live approval, with `--open` for public ones. See [Who can join](#who-can-join).
- 🤝 **Direct 2-peer links.** `ray connect <contact-id>` ties you to one person with no room id or invite, approved like a friend request. See [Direct 2-peer connections](#direct-2-peer-connections).
- 🌐 **Magic DNS.** Reach peers at `name.network.ray`, updated live as they join, leave, or rename.
- 🧱 **Per-device firewall.** A userspace firewall for mesh traffic, secure by default, layered on top of your host firewall. See [Firewall](#firewall).
- 🔑 **Mesh SSH, no keys.** Log in over the mesh with a stock `ssh` client; peers authenticate by identity. See [SSH, no keys](#ssh-no-keys).
- 🌍 **Exit nodes.** Route all your internet traffic through a peer that offers itself as a gateway: `ray exit-node allow` on the gateway, `ray exit-node use` on the client. Offering a gateway works on Linux, macOS and FreeBSD; using one works on Linux and macOS.
- 📜 **Declarative provisioning.** `ray apply deploy.yaml` stands up networks and firewall rules from a YAML spec, with reusable `aliases:` and `groups:` instead of repeated hostnames.
- 👥 **Multi-device identity.** Pair your laptop and phone under one identity, with encrypted key backup (optionally to 1Password). See [Pairing your own devices](#pairing-your-own-devices).
- 📁 **File sharing.** `ray send file.zip bob`, with optional auto-accept for transfers from your own paired devices.
- 📡 **mDNS** local discovery, and optional **Tor** transport.
- 🛠 **Operator model.** Run day-to-day commands without `sudo`, Tailscale-style. See [Permissions](#permissions).

## Quick start

Here's the whole tour: install once, create a network, invite a friend, and
reach each other by name. Two machines, about five minutes.

Rayfish runs on **Linux and macOS** (Android is early and experimental).
Building from source needs a Rust toolchain (2024 edition, Rust 1.85+); see
[Building](#building). Once the service is installed, `ray update` keeps it
current without rebuilding.

### 1. Install & start

Install the latest release, then bring the VPN up:

```bash
curl -fsSL https://rayfish.xyz/install.sh | sh
sudo ray up    # installs the system service if needed, then activates the VPN
```

The installer drops the `ray` binary in `/usr/local/bin` (override with
`INSTALL_DIR`) and verifies its checksum. It's [`install.sh`](install.sh) in
this repo, so you can read it before you run it. To build from source instead,
`cargo build` and see [Building](#building).

Only this first `ray up` needs root. It installs a small background service (the
daemon) that owns the network device and does the actual tunneling. From then on
everything runs as your normal user, including `ray up` and `ray down`.

Three levels of "on":

- `ray up` / `ray down` toggle the VPN itself. `down` is a quick standby: it drops
  the data plane (the tunnel and DNS) but keeps your peer connections warm, so
  `up` comes back near-instantly and needs no root.
- `sudo ray stop` / `sudo ray start` turn the whole daemon off and on. `stop` goes
  fully offline and closes every connection; `start` brings it all back.
  `sudo ray restart` is the two in one step (handy after changing config).

To update later, `sudo ray update` grabs the latest stable release, or
`sudo ray update --nightly` follows the bleeding edge. Both swap the binary and
restart the daemon for you. More on this just below.

#### Updating

```bash
ray --version            # show the installed version + git sha (also `ray version`)
ray update --check       # report current vs the latest GitHub release
ray update --list        # list available releases (newest first)
sudo ray update          # download + verify the latest stable release, swap the binary, restart the daemon
sudo ray update --nightly        # track the rolling nightly (rebuilt on every commit to master)
sudo ray update --version 0.1.0  # install a specific release (downgrades allowed)

sudo ray install --auto-update   # enable automatic stable updates at install time
ray auto-update on               # or toggle it any time (takes effect on `sudo ray restart`)
```

`ray update` fetches a release from GitHub, verifies its SHA-256, atomically replaces the running `ray` binary, and (if the system service is installed) restarts the daemon onto the new version. By default it tracks the latest stable release; `--nightly` follows the rolling pre-release built from every commit, and `--version X` pins a specific release. There is no persisted channel: each run picks its target from the flag. It needs root when the installed binary lives in a system path (so use `sudo ray update`); `ray --version`, `ray update --check`, and `ray update --list` do not.

**Automatic updates** are opt-in (off by default). Enable them with `sudo ray install --auto-update` or `ray auto-update on`: the daemon then checks for a newer **stable** release about every 6 hours and, when one exists, downloads + verifies + swaps the binary and restarts itself onto it. Nightlies are never auto-installed. Because applying an update restarts the daemon, it briefly drops the VPN (peers reconnect automatically), so it stays opt-in. `ray status` shows when auto-update is on.

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

`ray status` is also where the daemon nudges you about things that need
attention. A **pending** block at the bottom lists anything waiting on you, each
row telling you the exact command to deal with it:

```text
  rayfish  ● up      mDNS on      endpoint k7f2…9abc

  gentle-amber-fox  coordinator   alice   100.64.23.142   members 2/3
    ● bob      100.64.7.201   direct   12ms   ↑ 1.2 MB   ↓ 3.4 MB
    ○ carol    100.64.9.14
    join  <room-id>

  pending
    (1)  join request           ray requests gentle-amber-fox
    (1)  file offer             ray files
```

So if a friend runs `ray join <room-id>` and is sitting in your approval queue,
you don't have to go looking: `ray status` shows `(1) join request` and points
you straight at `ray requests gentle-amber-fox`. The same block surfaces
incoming file offers, connection requests, and coordinator firewall suggestions.

### 6. Leave or pause

```bash
ray leave gaming         # leave a network
ray kick gaming alice    # coordinator only: remove a member from a closed network (disconnects them mesh-wide)
ray ephemeral gaming 7d  # coordinator only: auto-remove members offline longer than 7d (off | show to disable/print)
ray down                 # standby: data plane (TUN + DNS) off, still connected to peers
ray up                   # reactivate (no root needed, near-instant: connections were kept)
sudo ray stop            # fully offline: daemon exits, peer connections close
sudo ray start           # back online: daemon restarts with both planes on
```

Run `ray --help` to discover the rest: `invite`, `requests`/`accept`/`deny`, `firewall`, `exit-node`, `apply`, `send`, `pair`, `mdns`, and more.

Prefer buttons and forms? Run `ray gui` to open a local browser GUI. It wraps
the same CLI commands, so anything available in `ray --help` is available there
too; commands that need root still need the GUI to be launched with `sudo`.

## Managing your network

Once a network exists, running it is a handful of commands. Here are the ones
you'll actually reach for.

### Public or private

`ray create` makes a **private** (closed) network by default. People can discover
it by its room id, but the id alone won't get them in: you decide who joins. Pass
`--open` for a **public** network that anyone with the room id can enter.

```bash
ray create                    # private: you approve every join
ray create --open             # public: anyone with the room id joins directly
```

Pick private for a homelab or a circle of friends, public for a community network
you're happy to leave the door open on. The three ways into a private network
(one-time invite, reusable key, live approval) are covered under
[Who can join](#who-can-join).

### Adding and removing people

```bash
ray invite <network>          # mint a one-time code to hand to one person
ray requests <network>        # see who's asking to join
ray accept <network> <id>     # let them in   (ray deny <id> to refuse)
ray kick <network> <member>   # remove someone for good; they drop mesh-wide
ray ephemeral <network> 7d    # auto-remove members offline longer than 7d
```

`ray kick` is the one to reach for when someone should lose access: it removes
them from the network's signed roster and every other member disconnects them.
`ray invite`, `ray requests`, `ray accept`, and `ray kick` are coordinator
actions, so you run them on the machine that created the network (or on any
co-coordinator you've added with `ray admin add`).

### Pairing your own devices

Pairing puts several of your own machines (laptop, desktop, phone) under a single
identity. They then share every network you belong to and show up as *you*, not
as separate members.

On a device that's already set up, start pairing:

```bash
ray pair                      # prints a ticket and a QR code, then waits
```

On the new device, scan the QR or paste the ticket:

```bash
ray pair <ticket>            # join your identity
ray pair list                # list the devices under your identity
ray unpair <device>          # revoke one later
```

Once paired, both devices are members of everything you've joined, and transfers
between them can land automatically (`ray files auto-accept <net> on`). Back the
shared identity key up with `ray pair backup` (optionally into 1Password) and
bring it onto a fresh machine with `ray pair restore`.

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

## Firewall

Rayfish ships a small userspace firewall that governs **mesh traffic only**. It
sits on top of your host/kernel firewall (a packet has to clear both), and it's
secure by default: unsolicited inbound TCP and UDP are denied, while inbound ICMP
(ping) and all outbound traffic are allowed. A stateful conntrack lets the return
traffic for connections you started back in.

So out of the box you can reach out to peers, but nothing reaches a port on your
machine until you open it. To expose a service you run, add an inbound allow rule:

```bash
ray firewall add in allow -p tcp --port 22                   # let peers reach your sshd
ray firewall add in allow -p tcp --port 8080 --peer alice    # only alice, only 8080
ray firewall reject on                                       # blocked connections fail fast instead of hanging
ray firewall                                                 # show the current rules
```

Rules are directional, per-port, and per-network; `--peer` scopes a rule to a
single peer. Don't want a second firewall at all? `ray firewall off` disables it
on that device. Full model: `ray firewall --help`.

**Coordinator suggestions.** A network's coordinator can suggest firewall rules
that ride the signed network record (a `*` subject targets every host). Each node
sees the pending suggestions in `ray status` and applies them, or opts into
auto-install with `--auto-accept-firewall`. Suggestions are advisory: your local
rules are never overwritten.

### SSH, no keys

`ray firewall ssh on` runs an embedded SSH server bound to your mesh IPs, and
`ray firewall ssh allow <network> <peer>` authorizes a peer to log in. Connect
with a stock client:

```bash
ssh user@host.ray
```

The peer is authenticated by its mesh identity, so there are no `authorized_keys`
to distribute (the same model as Tailscale SSH). One limitation to know: an
authorized peer may currently log in as **any** local user, so only enable it on
networks whose members you trust at that level.

## Declarative provisioning

For fleets and repeatable setups, `ray apply deploy.yaml` reconciles your
networks against a YAML spec instead of running commands by hand. It creates any
missing networks and publishes their firewall suggestions, so the spec is the
source of truth you can keep in git.

A spec has three top-level keys, all optional except `networks:`:

```yaml
# aliases: give a user a name that expands to all of their devices.
# Copy the identity from `ray identityof <net> <host>`.
aliases:
  alice: 7f3a9c01...          # alice, on every device she's paired

# groups: bundle aliases and/or literal hostnames under one name.
groups:
  admins: [alice, jumpbox]    # alice's devices plus a host named "jumpbox"

# networks: the real payload. Each network maps hostnames (the "subject") to
# the firewall rules other peers get toward that host.
networks:
  infra:
    "*":                      # "*" subject = every node in the network
      allows:
        admins: "tcp:22"      # the admins group may reach SSH on every host
  minecraft:
    "*":
      allows:
        "*": "tcp:6969"       # "*" peer = anyone; open 6969 mesh-wide
  gaming:
    alice:                    # a named host, not a wildcard
      allows:
        bob: "tcp:9000,tcp:8123"   # comma-separated proto:port tokens
      denies:
        eve: "icmp"
    carol: {}                 # empty subject = fully open, no rules
```

A few rules of thumb:

- Subject and peer keys are **hostnames** (or an alias/group that expands to
  them). `*` as a subject means every node; `*` as a peer means any peer.
- If a subject has an `allows:` list, it's an allow-list: only the listed peers
  get through, everything else is denied. `denies:` carves exceptions out.
- Aliases and groups are coordinator-side shorthand, expanded before publishing.
  They never travel over the mesh. An alias only resolves once that user has
  joined; literal hostnames work before anyone joins.

Run it, and iterate safely:

```bash
ray apply --example              # print a fully-commented starter spec
ray apply deploy.yaml --dry-run  # show what would change, apply nothing
ray apply deploy.yaml            # create missing networks, publish suggestions
ray apply deploy.yaml --invite-missing   # also mint invites for expected-but-absent hosts
ray apply deploy.yaml --prune            # drop suggestions for hosts no longer in the spec
```

Suggestions are still advisory on the receiving end: each node queues them for
`ray firewall accept`, or auto-installs them if it joined with
`--auto-accept-firewall`. `ray apply` never joins a node for you and never edits
a peer's local rules. To seed a spec's `aliases:` from a machine you're on,
`ray alias <net> set <host> <name>` saves the alias locally (it also shows inline
in `ray status`) so you don't have to paste the identity by hand.

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

## FAQ

> "You use LLMs? 🤯"

Yes. Heavily. Claude and GLM-5.2 wrote a lot of this repo.

> "So it's all vibe-coded slop."

The idea is over 4 years old: a trustless, decentralized network with no
central entity that can censor who you connect with. 
I sketched it for years. What an LLM changed was the *speed*: the prototype came together in a day.
The trigger was the release of [iroh v1](https://www.iroh.computer/blog/v1).

> "Is it actually trustless and serverless?"

Yes. By using iroh.

> ☝️🤓 actually, it is wrong to describe these P2P products as server-less.
> In order to connect two peers over WAN it needs a form of coordination server.

Who cares? To connect to the internet you need to go to through your ISP, the FBI, the NSA, the IRS, and any other 3 letter agency you can imagine in the world. But you care about n0 computer's servers... Sure.

You can also host your own relay and pkarr servers. Check [ansible-iroh](https://github.com/rayfish/ansible-iroh).
Your data is encrypted anyway. You own your identity.

> "Is rayfish production ready?"

NO. Don't use it in your company (yet!). Don't ditch tailscale or anything else to use it.

Use it in your homelab, with friends on a discord server or just to connect your android (in very alpha stage) and your laptop.

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) to report vulnerabilities privately.

## License

Rayfish is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0).
