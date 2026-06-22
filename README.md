# Rayfish

**A peer-to-peer mesh VPN with zero infrastructure.** Create a private virtual network, share a code, and your devices act like they're on the same LAN — no servers, no port forwarding, no static IPs.

```bash
ray create                 # you're the coordinator; get a join code
ray join <join-code>       # friends join with the code
ping alice.gaming.ray      # reach peers by name
```

---

## How it works

Rayfish is built on [iroh](https://iroh.computer) and connects peers by *cryptographic identity* rather than IP address. NAT traversal, hole-punching, and end-to-end encryption are handled for you; when a direct connection isn't possible (~10% of cases), traffic falls back to encrypted relays.

1. **Create** — one peer starts a network and becomes the coordinator. It gets a public-key *join code* to share.
2. **Join** — peers connect using the join code. iroh handles NAT traversal and encrypted transport.
3. **Mesh** — the coordinator assigns each peer a stable virtual IPv4 (`100.64.0.0/10`) and IPv6 (`200::/7`), then broadcasts the peer list. Every peer connects directly to every other.
4. **Use it** — any app over TCP/UDP just works, and Magic DNS lets you reach peers by `name.network.ray` instead of memorizing IPs.

Under the hood, each machine runs a daemon (similar to Tailscale's `tailscaled`) that creates a TUN device, captures IP packets, and tunnels them through iroh's QUIC-based P2P connections. Everything else — `create`, `join`, `status`, file sharing, ACLs — runs unprivileged and talks to the daemon over a local socket.

There's a lot more under the surface: distributed ACLs, a per-device firewall, multi-device identity via pairing, file sharing, mDNS local discovery, and optional Tor transport. See [docs/book.md](docs/book.md) for the full guide.

---

## Quick start

### 1. Install

```bash
cargo build
sudo ray up    # installs the system service if needed, then starts the daemon
```

> The **first** `ray up` needs root to install the system service and start the daemon (which creates the TUN device and owns the iroh endpoint). After that the daemon stays running, so every command — including `ray up` / `ray down` — runs unprivileged over a local socket. `down` puts the daemon on **standby** (TUN down, DNS reverted) without killing it; `up` reactivates it.

### 2. Create a network

```bash
ray create --hostname alice
# > Network created: gentle-amber-fox
# >   IPv4: 100.64.23.142
# >   IPv6: 200:ab3f:d92c:1e4a::1
# >   Hostname: alice.gentle-amber-fox.ray
# >   Join code: 3f8a...c7d2
# >   Share this join code to invite others
```

### 3. Join from another machine

```bash
ray join 3f8a...c7d2 --name gaming --hostname bob
# > Joined network 'gaming'.
# >   IPv4: 100.64.7.201
# >   Hostname: bob.gaming.ray
```

### 4. Reach each other

```bash
ray status               # see networks, peers, and traffic

ping alice.gaming.ray    # from the joiner — by name
ping bob.ray             # from the coordinator — flat lookup
ping 100.64.23.142       # or just by IP
```

### 5. Leave or pause

```bash
ray leave gaming         # leave a network
ray down                 # standby: TUN + DNS torn down, daemon keeps running
ray up                   # reactivate (no root needed)
```

That's the whole loop. Run `ray --help` to discover the rest (`acl`, `firewall`, `send`, `pair`, `mdns`, …).

---

## Building

```bash
cargo build                  # debug build
cargo build --features tor   # with optional Tor transport
```

Requires the Rust 2024 edition (Rust 1.85+).
