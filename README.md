# Rayfish

**A peer-to-peer mesh VPN with zero infrastructure.** Create a private virtual network, share a code, and your devices act like they're on the same LAN — no servers, no port forwarding, no static IPs.

```bash
ray create                 # you're the coordinator of a closed network
ray invite gaming          # mint a one-time invite code to hand out
ray join <invite-code>     # a friend joins with the code
ping alice.gaming.ray      # reach peers by name
```

---

## How it works

Rayfish is built on [iroh](https://iroh.computer) and connects peers by *cryptographic identity* rather than IP address. NAT traversal, hole-punching, and end-to-end encryption are handled for you; when a direct connection isn't possible (~10% of cases), traffic falls back to encrypted relays.

1. **Create** — one peer starts a network and becomes the coordinator. Networks are **closed by default**: the network's public key (the *room id*) lets peers discover the network but is **not** enough to join. Use `ray create --open` for a public network anyone with the room id can join directly.
2. **Join** — on a closed network a peer joins with a **one-time invite code** (`ray invite`) or by requesting approval (`ray requests` / `ray accept`). The coordinator is the gatekeeper: it verifies and burns invites and approves pending requests. iroh handles NAT traversal and encrypted transport.
3. **Mesh** — each peer derives its own stable virtual IPv4 (`100.64.0.0/10`) and IPv6 (`200::/7`) directly from its cryptographic identity, so addresses need no central assignment. The membership list is shared with everyone. Every peer connects directly to every other.
4. **Use it** — any app over TCP/UDP just works, and Magic DNS lets you reach peers by `name.network.ray` instead of memorizing IPs.

Under the hood, each machine runs a daemon (similar to Tailscale's `tailscaled`) that creates a TUN device, captures IP packets, and tunnels them through iroh's QUIC-based P2P connections. Everything else — `create`, `join`, `status`, file sharing — runs unprivileged and talks to the daemon over a local socket.

There's a lot more under the surface: a per-device firewall, trusted networks with coordinator-suggested firewall rules, declarative provisioning (`ray apply`), multi-device identity via pairing, file sharing, mDNS local discovery, and optional Tor transport. Run `ray --help` and see the [Quick start](#quick-start) below to explore.

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
ray create --hostname alice          # closed by default; add --open for a public network
# > ✓ network created gentle-amber-fox
# >   IPv4  100.64.23.142
# >   IPv6  200:ab3f:d92c:1e4a::1
```

### 3. Invite someone

```bash
ray invite gentle-amber-fox          # mint a single-use, expiring invite code
# > ✓ invite ab3f9c01
# >   <invite-code>
# >   single-use, expires in 7d
```

Hand the code to a friend. On a closed network they can also just `ray join <room-id>` to land in your approval queue — run `ray requests <network>` to see waiting peers and `ray accept <network> <id>` to let them in.

### 4. Join from another machine

```bash
ray join <invite-code> --name gaming --hostname bob
# > ✓ joined gaming
# >   IPv4  100.64.7.201
# >   IPv6  200:7c10:5e8b:33a1::1
```

### 5. Reach each other

```bash
ray status               # see networks, peers, and traffic

ping alice.gaming.ray    # from the joiner — by name
ping bob.ray             # from the coordinator — flat lookup
ping 100.64.23.142       # or just by IP
```

### 6. Leave or pause

```bash
ray leave gaming         # leave a network
ray down                 # standby: TUN + DNS torn down, daemon keeps running
ray up                   # reactivate (no root needed)
ray up --hostname dario  # set your default name for future create/join (collisions become dario-1, dario-2, …)
sudo ray restart         # restart the service (e.g. after upgrading the binary)
sudo ray install         # install/refresh the service and start it
sudo ray set-operator bob # let user 'bob' run ray without sudo
```

> `ray restart`, `ray install`, and `ray set-operator` need root because they manage the system service or grant access to it. `ray install` rewrites the unit file (or launchd plist) and restarts; `ray restart` only bounces the running service via `systemctl`/`launchctl` without touching the unit.
>
> **Who can run `ray`?** Like Tailscale, the daemon authorizes each command by the caller's UID, not by file permissions: `status` and other read-only commands are open to any local user, while mutating commands need root or the **operator**. The user who installs the service (`sudo ray up` / `ray install`) is granted operator access automatically, so they keep working without sudo. To authorize someone else, run `sudo ray set-operator <user>`.

That's the whole loop. Run `ray --help` to discover the rest (`invite`, `requests`/`accept`/`deny`, `firewall`, `apply`, `send`, `pair`, `mdns`, …).

### Controlling who can join

The network's **room id** (its public key) is a *discovery* key — it's published to the DHT so peers can find the network, but on a closed network it is **not** enough to get in. Admission is the coordinator's job.

- **Closed (default).** Someone joins one of two ways:
  - **Invite code** — `ray invite <network>` mints a **single-use, expiring** code (`bs58(room-id || coordinator || secret)`). Hand it over; the holder runs `ray join <code>`, the coordinator verifies and **burns** it. Great for unattended server provisioning — consume a token once, no clicks. Manage with `ray invite <network> list` and `ray invite <network> revoke <id>`.
  - **Live approval** — the holder of just the room id runs `ray join <room-id>` and lands in a queue. The coordinator runs `ray requests <network>`, then `ray accept <network> <id>` (or `ray deny`).
- **Open** (`ray create --open`) — anyone with the room id joins directly, no invite or approval. Good for public/community networks.

Either gate runs through the coordinator, so it must be online to admit a new peer; once admitted, a member reconnects by cryptographic identity and the coordinator can be offline.

### Something went wrong?

```bash
ray report               # bundle logs + metrics, open a pre-filled GitHub issue
```

The daemon writes rolling logs to `/var/log/rayfish/` (Linux) or `/Library/Logs/rayfish/` (macOS). `ray report` collects those logs, current metrics, and a sanitized status snapshot (**no private keys**) into a `.tgz`, then opens a pre-filled GitHub issue for you to attach it. The bundle is written locally first, so you can review it before sharing.

---

## Building

```bash
cargo build                  # debug build
cargo build --features tor   # with optional Tor transport
cargo build --features otel  # with OTLP span export
```

Requires the Rust 2024 edition (Rust 1.85+).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) to report vulnerabilities.

---

## License

Rayfish is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0).
