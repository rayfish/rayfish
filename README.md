# Rayfish

**A peer-to-peer mesh VPN with zero infrastructure.** Create a private virtual network, share a code, and your devices act like they're on the same LAN — no servers, no port forwarding, no static IPs.

Built on [iroh](https://iroh.computer), Rayfish connects peers by *cryptographic identity* rather than IP address. NAT traversal, hole-punching, and end-to-end encryption are handled for you. When a direct connection isn't possible (~10% of cases), traffic falls back to encrypted relays.

```bash
ray create                 # you're the coordinator; get a join code
ray join <join-code>       # friends join with the code
ping alice.gaming.ray      # reach peers by name
```

---

## Contents

- [Why Rayfish](#why-rayfish)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Features](#features)
  - [Multiple networks](#multiple-networks)
  - [Access control (ACL)](#access-control-acl)
  - [Local device firewall](#local-device-firewall)
  - [File sharing](#file-sharing)
  - [Magic DNS](#magic-dns)
  - [Device pairing](#device-pairing)
  - [Local peer discovery (mDNS)](#local-peer-discovery-mdns)
  - [Tor transport](#tor-transport)
- [Command reference](#command-reference)
- [Running as a service](#running-as-a-service)
- [Metrics](#metrics)
- [Configuration](#configuration)
- [Building](#building)
- [Architecture](#architecture)
- [Roadmap](#roadmap)

---

## Why Rayfish

You want to play Minecraft with friends, but nobody wants to set up port forwarding or pay for a hosted server. One person runs `ray create`, shares a short code, and everyone joins. Each player gets virtual IPv4 and IPv6 addresses, and the game thinks you're all on the same LAN.

It's not just for games. Rayfish gives you a private, encrypted network between any set of devices — laptops, home servers, cloud instances — without trusting a third party to route or store your traffic.

**What you get:**

- **No infrastructure** — no central server to run, pay for, or trust
- **Identity-based** — peers are addressed by public key, not IP
- **Dual-stack** — stable IPv4 (`100.64.0.0/10`) and IPv6 (`200::/7`) per peer
- **Magic DNS** — reach peers by `name.network.ray` instead of memorizing IPs
- **Full mesh** — every peer connects directly to every other peer
- **Multi-network** — run many isolated networks through one daemon
- **Access control** — coordinator ACLs plus a per-device firewall
- **Multi-device** — share one identity across your devices via pairing
- **Optional Tor** — route traffic through Tor for IP-level anonymity

---

## How it works

1. **Create** — one peer starts a network and becomes the coordinator.
2. **Share** — the creator gets a public-key *join code* to hand to friends.
3. **Join** — peers connect using the join code. iroh handles NAT traversal and encrypted transport.
4. **Mesh** — the coordinator assigns virtual IPs and broadcasts the peer list; every peer connects directly to every other.
5. **Use it** — each peer gets a virtual IPv4 and IPv6 address. Any app over TCP/UDP just works.

Under the hood, Rayfish creates a TUN device on each machine, captures IP packets, and tunnels them through iroh's QUIC-based P2P connections.

---

## Quick start

### Install on a server

```bash
just deploy <ip>    # cross-build, install binary, create rayfish group, start daemon
```

This installs the binary to `/usr/local/bin`, creates a `rayfish` group for socket access, and enables a systemd service that runs the daemon on boot.

Add your user to the group so you can run commands without `sudo`:

```bash
sudo usermod -aG rayfish $USER
# log out and back in, or: newgrp rayfish
```

### Install locally (macOS / development)

```bash
cargo build
sudo ray up    # installs the system service if needed, then starts the daemon
```

> `ray up` needs root (the daemon creates the TUN device and owns the iroh endpoint). Every other command runs unprivileged and talks to the daemon over a Unix socket.

### Basic usage

```bash
# Create a network — you become the coordinator
ray create --hostname alice
# > Network created: gentle-amber-fox
# >   IPv4: 100.64.23.142
# >   IPv6: 200:ab3f:d92c:1e4a::1
# >   Hostname: alice.gentle-amber-fox.ray
# >   Join code: 3f8a...c7d2
# >   Share this join code to invite others

# On another machine, join using the join code
ray join 3f8a...c7d2 --name gaming --hostname bob
# > Joined network 'gaming'.
# >   IPv4: 100.64.7.201
# >   Hostname: bob.gaming.ray

# See what's running
ray status

# Reach each other by name or IP
ping alice.gaming.ray    # from the joiner
ping bob.ray             # from the coordinator (flat lookup)

# Leave a network / shut down
ray leave gaming
ray down
```

---

## Features

### Multiple networks

Run several isolated networks at once through a single daemon:

```bash
ray create
ray create
ray status    # shows both networks with live peer info
```

Networks are fully isolated — separate encryption contexts, separate peer sets, no cross-talk.

### Access control (ACL)

Coordinators decide who can reach whom using identity- and tag-based rules:

```bash
# Tag peers by role
ray acl gaming tag servers ab3f... d92c...
ray acl gaming tag admins ee11...

# Allow rules (no rules = open; any rule = deny-all except what's allowed)
ray acl gaming allow admins all      # admins reach everyone
ray acl gaming allow all servers     # everyone reaches servers

ray acl gaming show                  # inspect current ACL
ray acl gaming apply                 # push changes to all peers
```

Rules are distributed via iroh-blobs and enforced at the packet-forwarding layer on every node. State persists to `~/.config/rayfish/acl/<network>.acl`.

### Local device firewall

Each device sets its own firewall rules, independent of the network ACL — so you protect your ports regardless of what the coordinator allows:

```bash
ray firewall default deny                              # block inbound by default
ray firewall add in allow --proto tcp --port 443       # allow HTTPS
ray firewall add in allow --proto tcp --port 22 --peer ab3f   # SSH from one peer
ray firewall add out allow                             # allow all outbound
ray firewall show
ray firewall remove 0
```

Evaluated first-match-wins. Supports TCP, UDP, ICMP, port ranges (e.g. `80-443`), and per-peer filters. Persists to `~/.config/rayfish/firewall.toml`.

> The `self` keyword refers to your own device in both ACL and firewall commands, e.g. `ray acl gaming tag servers self`.

### File sharing

Send files directly between peers over the mesh — no cloud, no size limits:

```bash
ray send photo.jpg alice          # send by hostname or short ID
ray files                         # list pending transfers
ray files accept 0                # accept, saves to ~/Downloads
ray files accept 0 --output .     # accept to current directory
```

Files are content-addressed (blake3) and transferred via iroh-blobs. The sender sends a lightweight offer (filename, size, MIME type, hash); the receiver inspects it before accepting. On accept, the blob is fetched directly from the sender and verified by hash.

### Magic DNS

Every peer gets a hostname under the `.ray` domain, so you never memorize an IP:

```bash
ray create --hostname alice
ray join 3f8a...c7d2 --hostname bob

ping alice.gentle-amber-fox.ray    # fully qualified
ping alice.ray                     # flat lookup across all networks
```

- **Stable & offline-resolvable** — hostnames propagate via the membership blob and persist across daemon restarts, so they resolve even when the named peer is offline.
- **Full record support** — A (IPv4), AAAA (IPv6), and PTR (reverse DNS), so `ping6` and `dig -x 100.64.x.x` both work. EDNS/OPT and DNS-over-TCP supported.
- **Collision-safe** — duplicate hostnames get a numeric suffix automatically (`alice` → `alice2`).
- **Non-invasive** — the daemon routes only `.ray` queries to its local resolver; all other DNS is untouched (macOS: SCDynamicStore; Linux: systemd-resolved / NetworkManager / resolvconf / direct `/etc/resolv.conf`).

### Device pairing

Use one identity across multiple devices. The primary signs a certificate for each secondary, so the network treats all your devices as one user:

```bash
ray pair                       # primary: shows a QR code + pairing ticket
ray pair <ticket>              # secondary: pair using the ticket
ray pair backup                # encrypt + back up your identity key
ray pair restore <backup-code> # restore on a new device
```

After pairing, ACL tags assigned to your user identity cover all your devices automatically. Each device still gets its own IP and connections.

### Local peer discovery (mDNS)

Peers on the same LAN are discovered via mDNS and connect directly, skipping relays for the lowest possible latency. Enabled by default:

```bash
ray mdns off     # disable
ray mdns on      # re-enable (restart daemon to apply)
```

### Tor transport

Route traffic through Tor for IP-level anonymity. Requires the `tor` build feature and a running Tor daemon:

```bash
cargo build --features tor
tor --ControlPort 9051 --CookieAuthentication 0   # in a separate terminal

ray create --tor --hostname alice
ray join 3f8a...c7d2 --tor --hostname bob
ray status                                        # shows [tor] for Tor-routed peers
```

Tor runs alongside the default relay transport and iroh picks the best path. Both peers must use `--tor` to communicate over Tor; otherwise they fall back to relay.

---

## Command reference

| Command | Description | Needs daemon |
|---------|-------------|:---:|
| `sudo ray up` | Install the service if needed and start it | — |
| `ray create [--tor]` | Create a network (generates name + join code) | Yes |
| `ray join KEY [--name ALIAS] [--tor]` | Join a network by join code | Yes |
| `ray leave NAME` | Leave a network and remove config | Yes |
| `ray nuke NAME [--force]` | Publish empty DHT records, then leave | Yes |
| `ray hostname NET NAME` | Change your hostname on a network | Yes |
| `ray status` | Show all networks, peers, traffic | No* |
| `ray down` | Shut down the daemon | Yes |
| `ray acl NAME tag TAG PEERS…` | Tag peers (coordinator) | Yes |
| `ray acl NAME allow SRC DST` | Add an allow rule (coordinator) | Yes |
| `ray acl NAME show` | Display ACL state | Yes |
| `ray acl NAME apply` | Push ACL changes to all peers | Yes |
| `ray send FILE PEER` | Send a file to a peer | Yes |
| `ray files` | List pending file transfers | Yes |
| `ray files accept ID` | Accept a file transfer | Yes |
| `ray firewall show` | Show local firewall rules | Yes |
| `ray firewall default ACTION` | Set default policy (allow/deny) | Yes |
| `ray firewall add DIR ACTION` | Add a firewall rule | Yes |
| `ray firewall remove INDEX` | Remove a rule by index | Yes |
| `ray pair [TICKET]` | Start pairing, or pair with a ticket | Yes |
| `ray pair backup` | Back up identity key (encrypted) | No |
| `ray pair restore CODE` | Restore identity from backup | No |
| `ray mdns on\|off` | Toggle mDNS local discovery | No |
| `sudo ray uninstall` | Stop and remove the system service | No |
| `ray completions SHELL` | Generate shell completions | No |

<sub>\* `ray status` shows saved networks even without a running daemon.</sub>

Commands other than the daemon run unprivileged — they talk to the daemon over a Unix socket at `/var/run/rayfish/rayfish.sock`. Users in the `rayfish` group have socket access.

---

## Running as a service

```bash
sudo ray up    # installs a systemd unit or launchd plist if missing, then starts it
```

The service runs `ray daemon` on boot, restoring all saved networks automatically. `just deploy <ip>` sets this up on Linux servers. Use `sudo ray uninstall` to stop and remove it.

---

## Metrics

The daemon exposes Prometheus-compatible metrics on port 9090:

```bash
curl http://localhost:9090/metrics
```

Includes forwarding counters (`rayfish_packets_rx_total`, `rayfish_bytes_tx_total`, `rayfish_drops_total{reason="acl"}`, …), per-peer gauges (`rayfish_peer_rtt_us`, `rayfish_peer_bytes_tx/rx`, `rayfish_peer_lost_packets`), and iroh transport metrics (`socket_*`, `net_report_*`). `ray status` also shows aggregate traffic stats.

---

## Configuration

| Path | Contents |
|------|----------|
| `~/.config/rayfish/networks.toml` | Network memberships |
| `~/.config/rayfish/secret_key` | Identity (Ed25519 keypair) — same endpoint ID across restarts |
| `~/.config/rayfish/acl/<network>.acl` | Per-network ACL rules |
| `~/.config/rayfish/firewall.toml` | Local firewall rules |

IPv4 and IPv6 addresses are both derived deterministically from peer identity, so they are stable and never change.

---

## Building

```bash
cargo build                  # debug build
cargo build --features tor   # with Tor transport
```

Requires the Rust 2024 edition (Rust 1.85+). Cross-compile and deploy to Linux servers:

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build + install + start daemon service
```

---

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x + 200::/7) → ray daemon → iroh QUIC datagrams → peer
```

Rayfish uses a daemon/client split similar to Tailscale. The daemon (`ray daemon`) is a long-lived root process that owns the iroh endpoint, TUN device, and all peer connections. CLI commands talk to it over a Unix socket.

- Full mesh topology — every peer connects directly to every other peer
- Coordinator assigns IPs and broadcasts the peer list over a QUIC control stream
- Data flows as QUIC datagrams (low-latency, no head-of-line blocking)
- Routing table dispatches packets by destination IP from IPv4 and IPv6 headers
- Split TUN I/O (`TunReader`/`TunWriter`) for lock-free concurrent read/write
- Per-network ALPN isolation on a single shared iroh endpoint
- Dynamic network management — create, join, and leave without restarting

---

## Roadmap

See [TODO.md](TODO.md) for the full roadmap. Current status:

- [x] Point-to-point tunnel between two peers
- [x] Multi-peer full mesh (N peers in one network)
- [x] Multiple simultaneous networks with isolation
- [x] Persistent network config
- [x] Public-key join codes for secure network sharing
- [x] DHT network records for offline coordinator resilience
- [x] Distributed ACLs with tag-based allow rules
- [x] Local device firewall with port/protocol/peer filtering
- [x] Magic DNS with `.ray` domain resolution
- [x] Dual-stack IPv6/IPv4 with stable addresses
- [x] Tor transport (optional, per-peer)
- [x] Systemd/launchd service integration
- [x] Daemon architecture with Unix socket IPC
- [x] mDNS local peer discovery
- [x] Multi-device identity via certificate-based pairing
- [ ] Social discovery (Discord, Slack, Steam)
- [ ] macOS Network Extension (no sudo)
- [ ] Windows, iOS, Android
