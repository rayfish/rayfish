# Pitopi

A peer-to-peer mesh VPN that lets you create private virtual networks without any infrastructure. Built on [iroh](https://iroh.computer), it connects peers by cryptographic identity — not IP addresses — so you never need to deal with port forwarding, dynamic DNS, or firewall rules.

## Why?

You want to play Minecraft with friends, but nobody wants to set up port forwarding or pay for a hosted server. With Pitopi, one person creates a network, shares a short code, and everyone joins. Each player gets virtual IPv4 and IPv6 addresses and the game thinks you're all on the same LAN.

But it's not just for games. Pitopi gives you a private, encrypted network between any set of devices — work machines, home servers, cloud instances — without trusting a third party.

## How it works

1. **Create a network** — one peer starts a network and becomes the coordinator
2. **Share the join code** — the creator gets a public key string to share with friends
3. **Join** — peers connect using the join code. iroh handles NAT traversal, hole-punching, and encrypted transport automatically
4. **Full mesh** — the coordinator assigns virtual IPs and broadcasts the peer list. Every peer connects directly to every other peer
5. **Use it** — every peer gets a virtual IPv4 (100.64.x.x) and IPv6 (200::/7) address. Any app that uses TCP/UDP just works

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
pitopi create --hostname alice
# > Network created: gentle-amber-fox
# >   IPv4: 100.64.23.142
# >   IPv6: 200:ab3f:d92c:1e4a::1
# >   Hostname: alice.gentle-amber-fox.pi
# >   Join code: 3f8a...c7d2
# >   Share this join code to invite others

# On another machine, join using the join code
pitopi join 3f8a...c7d2 --name gaming --hostname bob
# > Joined network 'gaming'.
# >   IPv4: 100.64.7.201
# >   IPv6: 200:e71a:f083:29b1::1
# >   Hostname: bob.gaming.pi

# Check what's running
pitopi status
# > Endpoint: <your-endpoint-id>
# >   gaming [coordinator] — alice.gaming.pi
# >     Peers:
# >       bob.gaming.pi (b3f2)

# Reach each other by name or IP
ping alice.gaming.pi    # from the joiner
ping bob.pi             # from the coordinator (flat lookup)

# Leave a network
pitopi leave gaming

# Shut down the daemon
pitopi down
```

### Multiple networks

You can run multiple isolated networks simultaneously through a single daemon:

```bash
pitopi create
pitopi create
pitopi status    # shows both networks with live peer info
```

Networks are fully isolated — different encryption contexts, different peer sets, no cross-talk.

### Access control

Coordinators can define who can reach whom within a network using identity/tag-based ACL rules:

```bash
# Tag peers by role
pitopi acl gaming tag servers ab3f... d92c...
pitopi acl gaming tag admins ee11...

# Allow rules (no rules = open; any rules = deny-all except allowed)
pitopi acl gaming allow admins all           # admins reach everyone
pitopi acl gaming allow all servers          # everyone reaches servers

# Show current ACL
pitopi acl gaming show

# Push changes to all peers
pitopi acl gaming apply
```

ACL rules are distributed to all peers via iroh-blobs and enforced at the packet forwarding layer on every node. ACL state is persisted to `~/.config/pitopi/acl/<network>.acl`.

### Local device firewall

Each device can set its own firewall rules independently of the network ACL. This lets you protect your ports regardless of what the coordinator allows:

```bash
# Block all inbound traffic by default
pitopi firewall default deny

# Allow inbound HTTPS and SSH from a trusted peer
pitopi firewall add in allow --proto tcp --port 443
pitopi firewall add in allow --proto tcp --port 22 --peer ab3f

# Allow all outbound
pitopi firewall add out allow

# Check current rules
pitopi firewall show

# Remove a rule by index
pitopi firewall remove 0
```

Rules are evaluated first-match-wins. Supports TCP, UDP, ICMP, port ranges (e.g. `80-443`), and per-peer filters. Firewall state is persisted to `~/.config/pitopi/firewall.toml`.

The `self` keyword can be used to reference your own device in ACL and firewall commands (e.g. `pitopi acl gaming tag servers self`).

### File sharing

Send files directly between peers over the mesh — no cloud storage, no size limits:

```bash
pitopi send photo.jpg alice          # send to peer by hostname or short ID
pitopi files                         # list pending incoming transfers
pitopi files accept 0                # accept, saves to ~/Downloads
pitopi files accept 0 --output .     # accept to current directory
```

Files are content-addressed (blake3) and transferred via iroh-blobs. The sender adds the file to the local blob store and sends a lightweight offer (filename, size, MIME type, hash) to the receiver. The receiver can inspect offers before accepting. On accept, the blob is fetched directly from the sender and verified by hash.

### Tor transport

Route all your network traffic through Tor for IP-level anonymity. Requires building with the `tor` feature and a running Tor daemon:

```bash
# Build with Tor support
cargo build --features tor

# Start Tor (in a separate terminal)
tor --ControlPort 9051 --CookieAuthentication 0

# Create a network over Tor
pitopi create --tor --hostname alice

# Join over Tor
pitopi join 3f8a...c7d2 --tor --hostname bob

# Status shows [tor] for Tor-routed connections
pitopi status
```

Tor runs alongside the default relay transport — iroh picks the best path automatically. Both peers must use `--tor` to communicate over Tor; otherwise they fall back to relay.

### Magic DNS

Every peer gets a hostname resolvable under the `.pi` domain. No more memorizing IPs:

```bash
# Create with a chosen hostname
pitopi create --hostname alice

# Join with a hostname
pitopi join 3f8a...c7d2 --hostname bob

# Now reach peers by name
ping alice.gentle-amber-fox.pi    # fully qualified
ping alice.pi                     # flat lookup (searches all networks)
```

Hostnames propagate via the membership blob and MeshHello messages — they're resolvable even when the named peer is offline. A (IPv4), AAAA (IPv6), and PTR (reverse DNS) records are served, so `ping6 alice.gaming.pi` and `dig -x 100.64.x.x` both work. EDNS/OPT and DNS-over-TCP are supported. If two peers choose the same hostname, a numeric suffix is appended automatically (e.g., `alice` → `alice2`). Hostnames persist across daemon restarts. The daemon configures your system DNS to route only `.pi` queries to its local resolver (macOS: SCDynamicStore, Linux: systemd-resolved/NetworkManager D-Bus, resolvconf, or direct); all other DNS is untouched.

### Device pairing

Use the same identity across multiple devices. The primary device signs a certificate for each secondary device, so all your devices share one identity for ACL purposes:

```bash
# On your primary device — displays a QR code and pairing ticket
pitopi pair

# On your secondary device — pair using the ticket
pitopi pair <ticket>

# Backup your identity key (encrypted with a passphrase)
pitopi pair backup

# Restore on a new device
pitopi pair restore <backup-code>
```

After pairing, ACL tags assigned to your user identity cover all your devices automatically. Each device still gets its own IP and connections, but the network treats them as one user.

### Local peer discovery (mDNS)

Pitopi automatically discovers other peers on your local network via mDNS. When two peers are on the same LAN, they connect directly — skipping relay servers entirely for the lowest possible latency.

This is enabled by default. To disable:

```bash
pitopi mdns off     # disable mDNS discovery
pitopi mdns on      # re-enable (restart daemon for changes to take effect)
```

## Commands

| Command | Description | Needs daemon |
|---------|-------------|:---:|
| `sudo pitopi daemon` | Start the daemon (owns TUN + endpoint) | — |
| `sudo pitopi up` | Alias for `daemon` | — |
| `pitopi create [--tor]` | Create a network (generates three-word name + join code) | Yes |
| `pitopi join KEY [--name ALIAS] [--tor]` | Join a network by public key join code | Yes |
| `pitopi leave NAME` | Leave a network and remove config | Yes |
| `pitopi nuke NAME [--force]` | Publish empty records to DHT then leave | Yes |
| `pitopi hostname NET NAME` | Change your hostname on a network | Yes |
| `pitopi status` | Show all networks (active + inactive), peers, traffic | No* |
| `pitopi down` | Shut down the daemon | Yes |
| `pitopi acl NAME tag TAG PEERS…` | Assign a tag to peers (coordinator) | Yes |
| `pitopi acl NAME allow SRC DST` | Add an allow rule (coordinator) | Yes |
| `pitopi acl NAME show` | Display current ACL state | Yes |
| `pitopi acl NAME apply` | Push ACL changes to all peers | Yes |
| `pitopi send FILE PEER` | Send a file to a peer | Yes |
| `pitopi files` | List pending incoming file transfers | Yes |
| `pitopi files accept ID` | Accept a file transfer | Yes |
| `pitopi firewall show` | Show local firewall rules | Yes |
| `pitopi firewall default ACTION` | Set default policy (allow/deny) | Yes |
| `pitopi firewall add DIR ACTION` | Add a firewall rule | Yes |
| `pitopi firewall remove INDEX` | Remove a rule by index | Yes |
| `pitopi pair` | Start device pairing (displays QR + ticket) | Yes |
| `pitopi pair TICKET` | Pair with a primary device | Yes |
| `pitopi pair backup` | Backup identity key (encrypted) | No |
| `pitopi pair restore CODE` | Restore identity from backup | No |
| `pitopi mdns on\|off` | Enable/disable mDNS local peer discovery | No |
| `pitopi install-service` | Install systemd/launchd service | No |
| `pitopi uninstall-service` | Remove system service | No |
| `pitopi completions SHELL` | Generate shell completions | No |

The daemon requires root (creates TUN devices). All other commands run unprivileged — they talk to the daemon over a Unix socket at `/var/run/pitopi/pitopi.sock`. Users in the `pitopi` group have socket access.

## Running as a service

```bash
sudo pitopi install-service    # installs systemd unit or launchd plist
```

The service runs `pitopi daemon` on boot, restoring all saved networks automatically. `just deploy <ip>` does this automatically on Linux servers.

## Metrics

The daemon exposes Prometheus-compatible metrics on port 9090:

```bash
curl http://localhost:9090/metrics
```

Includes pitopi forwarding counters (`pitopi_packets_rx_total`, `pitopi_bytes_tx_total`, `pitopi_drops_total{reason="acl"}`, etc.), per-peer gauges (`pitopi_peer_rtt_us`, `pitopi_peer_bytes_tx/rx`, `pitopi_peer_lost_packets`), and iroh transport metrics (`socket_*`, `net_report_*`). `pitopi status` also shows aggregate traffic stats.

## Configuration

Network memberships are stored at `~/.config/pitopi/networks.toml`. Identity (Ed25519 keypair) persists at `~/.config/pitopi/secret_key` — same endpoint ID across restarts. IPv4 and IPv6 addresses are both derived deterministically from peer identity, so they are stable and never change.

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
App (Minecraft, etc.) → TUN device (100.64.x.x + 200::/7) → pitopi daemon → iroh QUIC datagrams → peer
```

Pitopi uses a daemon/client split similar to Tailscale. The daemon (`pitopi daemon`) is a long-lived root process that owns the iroh endpoint, TUN device, and all peer connections. CLI commands talk to it over a Unix socket.

- Full mesh topology — every peer connects directly to every other peer
- Coordinator assigns IPs and broadcasts peer list via a control channel (QUIC bidirectional stream)
- Data flows as QUIC datagrams (low-latency, no head-of-line blocking)
- Routing table dispatches packets by destination IP from IPv4 and IPv6 headers
- Split TUN I/O (TunReader/TunWriter) for lock-free concurrent read/write
- Per-network ALPN isolation on a single shared iroh endpoint
- Dynamic network management — create, join, and leave without restarting

## Roadmap

See [TODO.md](TODO.md) for the full roadmap. Current status:

- [x] Point-to-point tunnel between two peers
- [x] Multi-peer full mesh (N peers in one network)
- [x] Multiple simultaneous networks with isolation
- [x] Persistent network config
- [x] Public key join codes for secure network sharing
- [x] DHT network records for offline coordinator resilience
- [x] Distributed ACLs with tag-based allow rules (coordinator-managed, enforced on all peers)
- [x] Local device firewall with port/protocol/peer filtering
- [x] Magic DNS with .pi domain resolution
- [x] Dual-stack IPv6/IPv4 with stable addresses
- [x] Tor transport (optional, per-peer)
- [x] Systemd/launchd service integration
- [x] Daemon architecture with Unix socket IPC
- [x] mDNS local peer discovery (LAN peers get direct connections automatically)
- [x] Multi-device identity via certificate-based pairing
- [ ] Social discovery (Discord, Slack, Steam)
- [ ] macOS Network Extension (no sudo)
- [ ] Windows, iOS, Android
