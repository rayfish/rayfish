# Pitopi

A peer-to-peer mesh VPN that lets you create private virtual networks without any infrastructure. Built on [iroh](https://iroh.computer), it connects peers by cryptographic identity — not IP addresses — so you never need to deal with port forwarding, dynamic DNS, or firewall rules.

## Why?

You want to play Minecraft with friends, but nobody wants to set up port forwarding or pay for a hosted server. With Pitopi, one person creates a network, shares a short code, and everyone joins. Each player gets a virtual IP and the game thinks you're all on the same LAN.

But it's not just for games. Pitopi gives you a private, encrypted network between any set of devices — work machines, home servers, cloud instances — without trusting a third party.

## How it works

1. **Create a network** — one peer starts a network and becomes the coordinator
2. **Share the code** — the creator gets a short room code (like `ybnj-raqe-...`) to share with friends
3. **Join** — peers connect using the room code. iroh handles NAT traversal, hole-punching, and encrypted transport automatically
4. **Full mesh** — the coordinator assigns virtual IPs and broadcasts the peer list. Every peer connects directly to every other peer
5. **Use it** — every peer gets a virtual IP (100.64.x.x). Any app that uses TCP/UDP just works

Under the hood, Pitopi creates a TUN device on each machine, captures IP packets, and tunnels them through iroh's QUIC-based P2P connections. If direct connections aren't possible (~10% of cases), traffic falls back to encrypted relay servers.

## Quick start

### Install on a server

```bash
just deploy <ip>    # cross-build, install binary, create pitopi group, start daemon
```

This installs `pitopi` to `/usr/local/bin`, creates a `pitopi` group for socket access, and enables a systemd service that runs the daemon on boot.

Add your user to the group so you can run commands without sudo:

```bash
sudo usermod -aG pitopi $USER
# log out and back in, or: newgrp pitopi
```

### Install locally (macOS / development)

```bash
cargo build
sudo pitopi daemon &    # start the daemon in the background
```

### Usage

```bash
# Create a network — you become the coordinator
pitopi create --name gaming
# > Network 'gaming' created.
# >   IP: 100.64.23.142
# >   Room code: gaming/ybnj-raqe-c5s6-...

# On another machine, join using the room code
pitopi join gaming/ybnj-raqe-c5s6-...
# > Joined network 'gaming'.
# >   IP: 100.64.7.201

# Check what's running
pitopi status
# > Endpoint: <your-endpoint-id>
# >   gaming [coordinator]
# >     IP: 100.64.23.142
# >     Peers:
# >       100.64.7.201 (<peer-endpoint-id>)

# Reach each other
ping 100.64.23.142    # from the joiner
ping 100.64.7.201     # from the coordinator

# Leave a network
pitopi leave gaming

# Shut down the daemon
pitopi down
```

### Multiple networks

You can run multiple isolated networks simultaneously through a single daemon:

```bash
pitopi create --name gaming
pitopi create --name work
pitopi status    # shows both networks with live peer info
```

Networks are fully isolated — different encryption contexts, different peer sets, no cross-talk.

## Commands

| Command | Description | Needs daemon |
|---------|-------------|:---:|
| `sudo pitopi daemon` | Start the daemon (owns TUN + endpoint) | — |
| `sudo pitopi up` | Alias for `daemon` | — |
| `pitopi create --name NAME` | Create a network (you become coordinator) | Yes |
| `pitopi join ROOM-CODE` | Join a network using a room code | Yes |
| `pitopi leave NAME` | Leave a network and remove config | Yes |
| `pitopi status` | Show active networks, peers, and IPs | Yes |
| `pitopi down` | Shut down the daemon | Yes |
| `pitopi list` | Show saved networks from config file | No |
| `pitopi install-service` | Install systemd/launchd service | No |
| `pitopi uninstall-service` | Remove system service | No |
| `pitopi completions SHELL` | Generate shell completions | No |

The daemon requires root (creates TUN devices). All other commands run unprivileged — they talk to the daemon over a Unix socket at `/var/run/pitopi/pitopi.sock`. Users in the `pitopi` group have socket access.

## Running as a service

```bash
sudo pitopi install-service    # installs systemd unit or launchd plist
```

The service runs `pitopi daemon` on boot, restoring all saved networks automatically. `just deploy <ip>` does this automatically on Linux servers.

## Configuration

Network memberships are stored at `~/.config/pitopi/networks.toml`. Identity (Ed25519 keypair) persists at `~/.config/pitopi/secret_key` — same endpoint ID across restarts.

## Building

```bash
cargo build
```

Requires Rust 2024 edition. Cross-compile and deploy to Linux servers:

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build + install + start daemon service
```

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x) → pitopi daemon → iroh QUIC datagrams → peer
```

Pitopi uses a daemon/client split similar to Tailscale. The daemon (`pitopi daemon`) is a long-lived root process that owns the iroh endpoint, TUN device, and all peer connections. CLI commands talk to it over a Unix socket.

- Full mesh topology — every peer connects directly to every other peer
- Coordinator assigns IPs and broadcasts peer list via a control channel (QUIC bidirectional stream)
- Data flows as QUIC datagrams (low-latency, no head-of-line blocking)
- Routing table dispatches packets by destination IP from the IPv4 header
- Split TUN I/O (TunReader/TunWriter) for lock-free concurrent read/write
- Per-network ALPN isolation on a single shared iroh endpoint
- Dynamic network management — create, join, and leave without restarting

## Roadmap

See [TODO.md](TODO.md) for the full roadmap. Current status:

- [x] Point-to-point tunnel between two peers
- [x] Multi-peer full mesh (N peers in one network)
- [x] Multiple simultaneous networks with isolation
- [x] Persistent network config
- [x] Room codes for easy sharing
- [x] DHT membership publishing for offline coordinator resilience
- [x] ACL policy engine and audit logging
- [x] Systemd/launchd service integration
- [x] Daemon architecture with Unix socket IPC
- [ ] Social discovery (Discord, Slack, Steam)
- [ ] macOS Network Extension (no sudo)
- [ ] Windows, iOS, Android
