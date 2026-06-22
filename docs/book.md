# The Rayfish Book

A complete guide to rayfish's architecture, protocols, and internals.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Identity](#3-identity)
4. [Membership](#4-membership)
5. [Transport](#5-transport)
6. [Control Protocol](#6-control-protocol)
7. [TUN Device](#7-tun-device)
8. [Packet Forwarding](#8-packet-forwarding)
9. [Peer Table](#9-peer-table)
10. [Configuration](#10-configuration)
11. [Three-Word Names](#11-three-word-names)
12. [Access Control](#12-access-control)
13. [Local Device Firewall](#13-local-device-firewall)
14. [File Sharing](#14-file-sharing)
15. [Magic DNS](#15-magic-dns)
16. [Audit Logging](#16-audit-logging)
17. [Statistics](#17-statistics)
18. [Shutdown](#18-shutdown)
19. [DHT Network Records](#19-dht-network-records)
20. [Network Lifecycle](#20-network-lifecycle)
21. [Daemon Architecture](#21-daemon-architecture)
22. [Code Flow Diagrams](#22-code-flow-diagrams)
23. [Security Model](#23-security-model)
24. [Device Pairing](#24-device-pairing)

---

## 1. Introduction

Rayfish is a peer-to-peer mesh VPN that creates private virtual networks without any centralized infrastructure. It is built on top of [iroh](https://iroh.computer), a library that provides encrypted QUIC-based peer-to-peer connectivity with automatic NAT traversal, hole-punching, and relay fallback.

The core idea is simple: every peer gets a virtual IP address derived from their cryptographic identity. When an application on your machine sends a packet to that virtual IP, rayfish captures it through a TUN device, looks up which peer owns that IP, and tunnels the packet over an encrypted QUIC connection to the right machine. To the application, it looks like all peers are on the same local network.

### The data path

```
Application (e.g., Minecraft)
    |
    v
TUN device (100.64.x.x / 200::x)
    |
    v
rayfish forwarding loop
    |  reads IPv4/IPv6 packets from TUN
    |  checks version nibble (4 or 6)
    |  extracts destination IP from header
    |  looks up the peer connection in the routing table (v4 or v6 DashMap)
    v
iroh QUIC datagram
    |  encrypted, NAT-traversed
    v
Remote peer's rayfish
    |  receives datagram
    |  writes packet to local TUN device
    v
Remote application
```

Rayfish uses QUIC datagrams (not streams) for data packets. Datagrams are unreliable and unordered -- just like UDP -- which means low latency and no head-of-line blocking. This makes rayfish well-suited for real-time applications like games.

### Address space

Rayfish is dual-stack: every peer gets both an IPv4 and an IPv6 address, each derived deterministically from their cryptographic identity.

**IPv4 — `100.64.0.0/10`:** The IANA-assigned Carrier-Grade NAT (CGNAT) block. This range is reserved for internal use by ISPs and is extremely unlikely to collide with any real network your machine participates in. The /10 prefix gives 22 bits of host address space (roughly 4 million unique addresses), derived via FNV-1a hash of the peer's identity.

**IPv6 — `200::/7`:** A 120-bit address space derived via blake3 hash. The large address space makes collisions practically impossible. IPv6 addresses are stable and never rotate -- the same identity always produces the same address. Applications can use either address family to reach a peer.

### Why not WireGuard?

WireGuard is excellent for static, pre-configured tunnels between known endpoints. Rayfish solves a different problem: you don't know your peers' IP addresses, you don't want to configure port forwarding, and you want peers to find each other by cryptographic identity alone. iroh handles the hard part -- discovering peers through relay servers, punching through NATs, and falling back to relayed connections when direct paths aren't possible.

### Network topology

A user can be part of multiple networks simultaneously. Each network is an independent full mesh -- every peer connects directly to every other peer. Networks are completely isolated from each other (different ALPNs, different member lists).

Your device sits at the center of all your networks. Each network is a full-mesh bubble, and you participate in all of them simultaneously:

```
  .-------------------------------------. .-------------------------------------.
  |        My gaming network :)          | |         My work network :(          |
  |                                      | |                                     |
  |          (Friend 1)                  | |           (Co-worker 1)             |
  |           /  |  \                    | |             /   |   \               |
  |          /   |   \                   | |            /    |    \              |
  |         /    |    \                  | |           /     |     \             |
  | (Minecraft)  |  (Your)--------------+-+---(Your)--    (Company)             |
  |  (server)----|  (device)             | |   (device)\    |    (server 1)     |
  |         \    |    /                  | |            \   |     /              |
  |          \   |   /                   | |             \  |    /               |
  |           \  |  /                    | |           (Co-worker 2)             |
  |          (Friend 2)                  | |                |                    |
  |                                      | |             (Company)              |
  |  every peer <---> every peer         | |             (server 2)             |
  '--------------------------------------' '-------------------------------------'
```

One rayfish process, one TUN device, one routing table -- shared across all your networks.

### Enterprise use case

In a company, different departments run separate networks. Shared services (like Jenkins) join multiple networks, sitting at the overlap:

```
  .-------------------------------. .-------------------------------.
  |         Accounting            | |          Technology            |
  |                               | |                               |
  | (server) (server) (server)    | |    (server) (server) (server) |
  |                               | |                               |
  | (User 1) (User 2) (User 3)   | |   (User 1) (User 2) (User 3) |
  |                       .-------+-+-------.                       |
  |                       |    (Jenkins)    |                       |
  '-----------------------|                 |-----------------------'
                          '-------+-+-------'
                     .------------+-+----------------------------.
                     |          Webpage                          |
                     |                                           |
                     |  (server) (server) (server)               |
                     |                                           |
                     |  (User 1) (User 2) (User 3)              |
                     '-------------------------------------------'

  Jenkins is a member of ALL THREE networks.
  It can reach accounting servers, tech servers, and web servers.
  But User 1 in "accounting" CANNOT reach servers in "technology" --
  networks are isolated unless a device explicitly joins both.
```

### Joining a network (invitation)

The coordinator creates a network and gets a join code (the network's public key). That join code is the invitation:

```
                                         .-------------------------.
                                         |    User's network       |
  (Friend 1) <--- invitation ---------- |                         |
                   (public key)          |     (User's device)     |
                                         |                         |
                                         '-------------------------'

  1.  User creates network:    ray create
      --> prints network name: gentle-amber-fox
      --> prints join code: <public-key-string>

  2.  User shares join code with Friend 1 (chat, email, etc.)

  3.  Friend 1 joins:          ray join <public-key> --name gaming
      --> daemon resolves pkarr record via public key
      --> fetches GroupBlob from online seed peers via iroh-blobs
      --> coordinator approves (or peer welcomes if already approved)
      --> Friend 1 gets Welcome (member list, approved list)
      --> Friend 1 connects to all existing peers
      --> full mesh established
```

### Per-node architecture

Inside each peer, the stack looks like this:

```
┌─────────────────────────────────────────────────┐
│                  Applications                    │
│            (Minecraft, SSH, curl, ...)            │
└──────────────────────┬──────────────────────────┘
                       │ regular TCP/UDP to 100.64.x.x or 200::x
                       ▼
┌─────────────────────────────────────────────────┐
│               TUN device (kernel)                │
│  100.64.0.0/10 (IPv4) + 200::/7 (IPv6)          │
│  captures all traffic to the virtual ranges      │
└──────┬──────────────────────────────┬────────────┘
       │ read                         │ write
       ▼                              ▼
┌─────────────┐               ┌─────────────┐
│  TunReader  │               │  TunWriter  │
│  (run_mesh) │               │  (tun_rx)   │
└──────┬──────┘               └──────▲──────┘
       │                              │
       │ dst_ip → PeerTable            │ tun_tx channel
       │ lookup_v4/v6 → Connection    │
       ▼                              │
┌─────────────────────┐    ┌──────────┴──────────┐
│    PeerTable        │    │  spawn_peer_reader   │
│  ┌───────────────┐  │    │  (one per peer)      │
│  │100.64.23.5    │──┼──▶ │                      │
│  │  → conn to A  │  │    │  conn.read_datagram()│
│  │100.64.87.12   │  │    │    → tun_tx.send()   │
│  │  → conn to B  │  │    └─────────────────────┘
│  │100.64.42.200  │  │
│  │  → conn to C  │  │
│  └───────────────┘  │
└──────────┬──────────┘
           │ conn.send_datagram()
           ▼
┌─────────────────────────────────────────────────┐
│              iroh QUIC endpoint                  │
│    NAT traversal, hole-punching, relay fallback  │
│    TLS 1.3 + Ed25519 identity authentication     │
└──────────────────────┬──────────────────────────┘
                       │ encrypted UDP
                       ▼
                   Internet
```

---

## 2. Getting Started

### Building

```bash
cargo build
```

Requires Rust 2024 edition.

### Starting the daemon

Before using any network commands, start the service:

```bash
sudo ray up
```

`ray up` installs the system service (a systemd unit on Linux, a launchd plist on macOS) if it isn't already present, then starts it. The service runs `ray daemon`, a long-lived process that owns the iroh endpoint, TUN device, and all peer connections. It listens for commands on a Unix socket at `/var/run/rayfish/rayfish.sock`. On startup, it restores all previously saved networks from config.

`ray daemon` runs the daemon loop in the foreground and is invoked by the service — you normally use `ray up` rather than calling it directly. To stop and remove the service, run `sudo ray uninstall`.

### Creating a network

In another terminal, create a network:

```bash
ray create
```

Or create with a custom name:

```bash
ray create --name gaming
```

This produces output like:

```
Network 'gaming' created.
  IP: 100.64.23.142
```

The daemon automatically generates a three-word name (adjective-noun-noun) and publishes the network to the DHT. The coordinator's IP is deterministically derived from their cryptographic identity.

### Joining a network

Other peers join by providing the three-word name:

```bash
ray join gentle-amber-fox
```

The daemon resolves the name via the directory DHT, fetches the current member list from online peers, connects to the coordinator (or any peer), receives approval and a member list, and establishes direct connections to every other peer in the mesh.

### Nuking a network

To permanently remove a network and announce its removal to all peers:

```bash
ray nuke gentle-amber-fox
```

This publishes empty membership and seed list records to the DHT (so new joiners know the network no longer exists), then leaves the network. Use `--force` to skip the confirmation prompt.

### Checking status

Once you have networks running, query the daemon for live state:

```bash
ray status
# > Endpoint: <your-endpoint-id>
# >   gaming [coordinator] — alice.gaming.ray
# >     Peers:
# >       bob.gaming.ray (b3f2)
```

Peers are shown by DNS name when available (hostname.network.ray), falling back to IP for peers without a hostname.

### Leaving a network

```bash
ray leave gaming
```

This tears down all connections for that network, removes peers from the routing table, and deletes it from the saved config.

### Shutting down

```bash
ray down    # signals the daemon to shut down gracefully
```

### Socket permissions

The daemon runs as root and creates the IPC socket at `/var/run/rayfish/rayfish.sock`. By default, only root can connect. To allow unprivileged users to run commands, create a `rayfish` group and add users to it:

```bash
sudo groupadd rayfish
sudo usermod -aG rayfish $USER
# log out and back in, or: newgrp rayfish
```

The daemon automatically sets the socket to `root:rayfish` with mode `0660` if the group exists.

### Why sudo?

TUN devices are virtual network interfaces. Creating them requires root privileges on both Linux and macOS. Only `ray up` (and the service-internal `ray daemon`) requires root. All other commands are thin IPC clients that talk to the daemon and run unprivileged.

### All commands

| Command | Description | Needs daemon |
|---------|-------------|:---:|
| `sudo ray up` | Install the service if needed and start it | — |
| `ray create [--name NAME]` | Create a network (custom or random name + join code) | Yes |
| `ray join KEY [--name ALIAS]` | Join a network by public key | Yes |
| `ray leave NAME` | Leave a network and remove config | Yes |
| `ray nuke NAME [--force]` | Publish empty record to DHT then leave | Yes |
| `ray status` | Show all networks (active + inactive), peers, traffic | No* |
| `ray down` | Shut down the daemon | Yes |
| `ray acl NAME tag TAG PEERS…` | Assign a tag to one or more peers | Yes |
| `ray acl NAME untag TAG PEERS…` | Remove a tag from peers | Yes |
| `ray acl NAME allow SRC DST` | Add an allow rule | Yes |
| `ray acl NAME remove INDEX` | Remove a rule by index | Yes |
| `ray acl NAME show` | Display current ACL state | Yes |
| `ray acl NAME apply` | Re-publish current ACL to all peers | Yes |
| `ray mdns on\|off` | Enable/disable mDNS local peer discovery | No |
| `sudo ray uninstall` | Stop and remove the system service | No |
| `ray completions SHELL` | Generate shell completions | No |

### Deploying to servers

```bash
just deploy <ip>    # cross-build + install + create rayfish group + start daemon service
```

This handles everything: builds for x86_64 Linux, installs the binary, creates the `rayfish` group, installs a systemd service, and starts the daemon. On subsequent deploys it restarts the service to pick up the new binary.

---

## 3. Identity

**Module:** `src/identity.rs`

Every rayfish node has a persistent Ed25519 keypair stored at `~/.config/rayfish/secret_key`. This keypair is the node's cryptographic identity -- it determines the node's EndpointId and, by extension, its virtual IP address.

### Key generation and persistence

The first time rayfish runs, it generates a random Ed25519 secret key and writes the raw 32 bytes to disk:

```
~/.config/rayfish/secret_key  (32 bytes, binary)
```

On subsequent runs, it loads the existing key. This means a node always has the same EndpointId and the same virtual IP across restarts, reboots, and even machine migrations (as long as you copy the key file).

### EndpointId

The public half of the Ed25519 keypair is the node's `EndpointId`. This is what iroh uses to identify and route to the node. It's a 32-byte value that can be displayed as a hex string or encoded as a z-base-32 room code.

The EndpointId serves dual purpose:

1. **Network address:** iroh uses it to locate and connect to the peer, handling NAT traversal and relay automatically.
2. **Identity root:** the virtual IP is deterministically derived from it, and all membership records reference it as the peer's identity string.

### Security properties

The secret key never leaves the machine. All authentication happens at the QUIC transport layer -- when two peers connect, iroh performs a mutual TLS handshake using their Ed25519 keys. A peer's EndpointId is the public key from this handshake, so a peer cannot impersonate another peer's identity at the transport level.

---

## 4. Membership

**Module:** `src/membership.rs`

The membership module is the heart of rayfish's identity and authorization system. It defines how peers are identified, how their IP addresses are assigned, and who is allowed to join a network.

### Identity-derived IP addresses

Rather than assigning IPs sequentially (first joiner gets .2, second gets .3), rayfish derives each peer's addresses deterministically from their cryptographic identity.

#### IPv4 derivation (FNV-1a)

```
identity string  ->  FNV-1a hash  ->  lower 22 bits  ->  100.64.0.0/10 address
```

The FNV-1a algorithm was chosen for its simplicity (no external dependencies), good distribution, and determinism. The 22-bit host space maps directly to the /10 CGNAT range.

Two host addresses are reserved:
- `100.64.0.0` -- network address (host bits = 0)
- `100.64.0.1` -- TUN gateway address (host bits = 1)

If the hash lands on either of these, the address is shifted to host bits 2 or 3.

The `derive_ip_with_index(identity, index)` variant supports collision rotation by mixing an index into the hash, enabling future automatic collision resolution without changing identities.

#### IPv6 derivation (blake3)

```
identity string  ->  blake3 hash  ->  15 bytes  ->  prepend 0x02  ->  200::/7 address
```

The blake3 hash provides 120 bits of address space within the `200::/7` range, making collisions practically impossible. IPv6 addresses are derived on-demand via `derive_ipv6()` rather than stored in the `Member` struct -- any peer can compute another peer's IPv6 address from their identity alone.

The key property: **a peer always gets the same IPv4 and IPv6 addresses, in every network, on every run.** This makes both addresses stable identifiers that other peers and applications can rely on.

#### Collision handling

With 22 bits of address space and a hash function, collisions are possible. The birthday problem gives roughly a 50% collision probability around 2,000 peers. For rayfish's target use case (small groups of friends or coworkers), this is extremely unlikely, but the system handles it gracefully at two levels:

1. **Coordinator-side check:** Before broadcasting a `MemberApproved` message, the coordinator checks the derived IP against both the member list and the approved list. If a collision is found with a different identity, the peer receives a `JoinDenied` with the reason "IP collision" and the approval is never broadcast.

2. **Joiner-side check:** When a peer receives a `Welcome` message containing the member list, it checks its own derived IP against all existing members. If a collision is detected, the joiner bails out with an error rather than entering the mesh. This serves as a defense-in-depth check and is the primary collision guard when the joiner connects via a non-coordinator peer.

The `MemberList::add()` method enforces collision detection at the data structure level: it rejects any addition where a *different* identity already occupies the same IP. Re-adding the same identity with the same IP is allowed (idempotent update).

### The IdentityProvider trait

All identity operations are abstracted behind a trait to allow swapping the identity backend:

```rust
pub trait IdentityProvider: Send + Sync {
    fn local_ip(&self) -> Ipv4Addr;
    fn local_ipv6(&self) -> Ipv6Addr;
    fn local_identity(&self) -> EndpointId;
    fn derive_ip(&self, peer_identity: &EndpointId) -> Ipv4Addr;
    fn derive_ipv6(&self, peer_identity: &EndpointId) -> Ipv6Addr;
}
```

The current implementation, `IrohIdentityProvider`, wraps an iroh `EndpointId`:

- `local_ip()` returns the FNV-1a-derived IPv4 for this node's EndpointId.
- `local_ipv6()` returns the blake3-derived IPv6 for this node's EndpointId.
- `local_identity()` returns the EndpointId (iroh `PublicKey`).
- `derive_ip(peer)` converts the EndpointId to a string internally and hashes it to an IPv4.
- `derive_ipv6(peer)` computes the blake3-derived IPv6 for any peer's EndpointId.

Identity verification happens at the transport level — the QUIC handshake already authenticates the EndpointId, so `conn.remote_id()` is trusted without additional application-level checks.

### MemberList

The `MemberList` is an in-memory registry of all members in a network:

```rust
pub struct Member {
    pub identity: EndpointId,   // iroh public key
    pub ip: Ipv4Addr,           // derived from identity
    pub is_coordinator: bool,   // whether this member created the network
}
```

The list is stored as a `HashMap<EndpointId, Member>` keyed by identity. It supports:

- `add(member)` -- insert with IP collision detection
- `remove(identity)` -- remove a member
- `get(identity)` -- lookup by identity string
- `get_by_ip(ip)` -- lookup by virtual IP
- `is_member(identity)` -- membership check
- `all()` -- list all members

### ApprovedList

The `ApprovedList` tracks peers that have been approved by the coordinator but haven't connected to the mesh yet. This is the key data structure behind the "coordinator as gatekeeper" model -- it decouples authorization from welcome.

```rust
pub struct ApprovedEntry {
    pub identity: EndpointId,   // iroh public key
    pub ip: Ipv4Addr,           // derived from identity
}
```

The list is stored as a `HashMap<EndpointId, ApprovedEntry>` keyed by identity. It supports:

- `approve(entry, &MemberList)` -- add with collision check against both the member list and existing approved entries
- `is_approved(identity)` -- check if a peer is pre-approved
- `remove(identity)` -- remove an entry (used when promoting to full member)
- `all()` -- list all approved entries
- `from_entries(entries)` -- bulk load from a vector

The approve-then-promote lifecycle:

1. Coordinator approves a peer → entry added to `ApprovedList`
2. Coordinator broadcasts `MemberApproved` → all peers add the entry to their local approved lists
3. Approved peer connects to any peer → welcoming peer removes from `ApprovedList`, adds to `MemberList`
4. Welcoming peer broadcasts `MemberSync` → all peers update their member lists

### GroupBlob and canonical serialization

`GroupBlob` is the canonical, serializable form of all network state. It is serialized to msgpack (sorted by identity for determinism), stored in the iroh-blobs store, and blake3-hashed to produce the hash published to the pkarr record.

```rust
pub struct GroupBlob {
    pub members: Vec<Member>,
    pub approved: Vec<ApprovedEntry>,
    pub acl: AclData,
}
```

`canonical_group_bytes()` produces the canonical msgpack bytes for hashing and storage. `group_blob_hash()` computes the blake3 hash. `verify_group_blob()` verifies the hash and deserializes. The GroupBlob contains no secrets — the per-network secret key is persisted only in the coordinator's config.

### NetworkState

The `MemberList` and `ApprovedList` are bundled into a `NetworkState` struct and shared across async tasks using `Arc<std::sync::RwLock<NetworkState>>`:

```rust
struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
}
```

The standard library `RwLock` (not tokio's) is used because all operations are fast, non-blocking, and never hold the lock across an `.await` point.

### Group modes

Networks can operate in one of two membership modes:

**Restricted (default):** Only the coordinator can authorize new members. However, any peer can *welcome* an already-approved member. This means the coordinator doesn't need to be online when the approved peer actually connects -- it just needs to have broadcast the approval beforehand.

**Open:** Any member can both authorize and welcome new joiners. When a connection comes in, any peer that receives it checks the `MembershipPolicy` and, if they're authorized (which all members are in Open mode), they can approve and welcome the peer directly.

The mode is selected at network creation:

```bash
sudo ray create --name gaming --mode open
```

### The MembershipPolicy trait

Authorization is abstracted behind a trait:

```rust
pub trait MembershipPolicy: Send + Sync {
    fn can_authorize(&self, acceptor: &Member) -> bool;
}
```

Two implementations exist:

- `OpenPolicy` -- always returns `true`. Any member can accept new peers.
- `RestrictedPolicy` -- returns `true` only if `acceptor.is_coordinator` is `true`.

The `policy_for_mode()` function creates the right policy for a given `GroupMode`:

```rust
pub fn policy_for_mode(mode: GroupMode) -> Box<dyn MembershipPolicy> {
    match mode {
        GroupMode::Open => Box::new(OpenPolicy),
        GroupMode::Restricted => Box::new(RestrictedPolicy),
    }
}
```

---

## 5. Transport

**Module:** `src/transport.rs`

The transport layer wraps iroh's `Endpoint` to provide peer-to-peer QUIC connectivity with automatic NAT traversal.

### Endpoints

An iroh `Endpoint` is the local end of the P2P network. It binds to a UDP socket, registers with iroh's relay infrastructure for peer discovery, and handles NAT hole-punching. A single endpoint can serve multiple networks simultaneously by accepting connections on different ALPNs.

The endpoint is created with:
- The node's `SecretKey` (Ed25519 private key)
- A list of ALPNs (one per network the node participates in)

### ALPN-based network isolation

Each rayfish network gets its own ALPN (Application-Layer Protocol Negotiation) string:

```
rayfish/net/<pubkey-prefix>
```

The ALPN uses the first 16 hex characters of the network's public key. For example, `rayfish/net/aa8bc368fec8c227`. When a connection arrives, rayfish checks the ALPN to determine which network it belongs to and routes it accordingly. Since the ALPN is derived from the public key (which all peers share via the join code), it matches regardless of local aliases.

This allows a single iroh endpoint to participate in multiple networks without interference. Connection attempts for one network are invisible to another.

### Connection model

Rayfish uses two types of QUIC channels:

1. **Bidirectional streams** -- for control messages (join requests, member syncs, mesh hellos). These are reliable and ordered, suitable for the structured JSON messages that coordinate membership.

2. **Datagrams** -- for data packets (the actual network traffic tunneled through the VPN). These are unreliable and unordered, providing the lowest possible latency.

### NAT traversal

iroh handles NAT traversal automatically. The typical flow:

1. Peers register with relay servers, which store their contact information.
2. When peer A wants to connect to peer B, it looks up B's relay information.
3. iroh attempts direct UDP hole-punching between the two peers.
4. If direct connection fails (about 10% of cases), traffic flows through the relay server, still fully encrypted end-to-end.

This means rayfish works without any port forwarding, dynamic DNS, or firewall configuration.

### Tor transport

Rayfish supports routing traffic through the Tor network for IP-level anonymity. This is an optional feature enabled at build time with `--features tor` and at runtime with the `--tor` flag on `create` or `join`.

When Tor is enabled, the daemon:
1. Connects to a local Tor daemon via the control port (9051)
2. Creates a Tor hidden service derived from the iroh SecretKey
3. Adds the Tor transport alongside the default relay transport

The Tor onion address is derived deterministically from the iroh identity — no separate address discovery or exchange is needed. Any EndpointId maps to exactly one onion address. iroh's path selection runs both transports simultaneously and picks the best path (Tor has higher RTT, so relay wins when both are available).

**Requirements:**
- Build with `cargo build --features tor`
- A running Tor daemon: `tor --ControlPort 9051 --CookieAuthentication 0`

**Usage:**
```bash
ray create --tor --hostname alice
ray join <key> --tor --hostname bob
```

The `--tor` preference is saved per-network in `networks.toml`. On daemon restart, if any saved network uses Tor, the Tor transport is automatically enabled.

---

## 6. Control Protocol

**Module:** `src/control.rs`

The control protocol handles all coordination between peers: join requests, membership updates, and mesh formation. Messages are sent as length-prefixed msgpack over QUIC bidirectional streams.

### Wire format

```
[4 bytes: big-endian u32 length] [N bytes: msgpack body]
```

The 4-byte length prefix allows the receiver to know exactly how many bytes to read for each message. Maximum message size is 64 KB.

### Message types

#### Welcome

Sent by any peer to a newly connecting approved peer. This is the primary join message in the gatekeeper model:

```json
{
    "Welcome": {
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false }
        ],
        "approved": [
            { "identity": "jkl012...", "ip": "100.64.7.99" }
        ]
    }
}
```

The `members` list contains every current member. The `approved` list contains peers that have been approved but haven't connected yet. The joiner checks its own derived IP against the member list for collision detection.

#### MemberApproved

Broadcast by the coordinator to all connected peers when a new identity is approved:

```json
{
    "MemberApproved": {
        "identity": "def456...",
        "ip": "100.64.23.142"
    }
}
```

Receiving peers add this entry to their local `ApprovedList`. When the approved peer later connects to any of them, they can welcome that peer without needing the coordinator to be online.

#### JoinApproved (legacy)

The original join message, retained for backward compatibility with older peers:

```json
{
    "JoinApproved": {
        "your_ip": "100.64.23.142",
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false }
        ]
    }
}
```

New coordinators send `Welcome` instead. Joiners accept both formats.

#### JoinDenied

Sent when a join is rejected:

```json
{
    "JoinDenied": {
        "reason": "IP collision"
    }
}
```

Reasons include "not authorized" (policy rejection) and "IP collision: 100.64.x.x already assigned" (hash collision with an existing member or approved peer).

#### MemberSync

Broadcast to all existing peers when the member list changes. Also sent to reconnecting peers:

```json
{
    "MemberSync": {
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false },
            { "identity": "ghi789...", "ip": "100.64.7.42", "is_coordinator": false }
        ]
    }
}
```

This is the primary mechanism for keeping all peers' view of the network in sync.

#### MeshHello

Sent by a newly joining peer to each existing mesh member (including the coordinator) to establish a direct connection and announce its hostname:

```json
{
    "MeshHello": {
        "identity": "def456...",
        "ip": "100.64.23.142",
        "hostname": "tide"
    }
}
```

The receiving peer adds the sender to its routing table and spawns a datagram reader for the connection. On the coordinator side, `spawn_coordinator_hello_reader()` accepts the MeshHello, resolves hostname collisions, updates the member list, and registers the hostname in the DNS table.

#### MeshWelcome

The response to a `MeshHello`:

```json
{
    "MeshWelcome": {
        "identity": "abc123...",
        "ip": "100.64.10.5"
    }
}
```

#### ReconnectRequest

Sent by a peer that was previously a member and is reconnecting after a disconnection:

```json
{
    "ReconnectRequest": {
        "identity": "def456...",
        "ip": "100.64.23.142"
    }
}
```

The receiving peer checks whether the sender is in the known member list. If so, it adds them to the routing table and sends back a `MemberSync` with the current member list. If not, the request is rejected.

#### AdvertiseServices

Allows peers to announce services they're running:

```json
{
    "AdvertiseServices": {
        "ip": "100.64.10.5",
        "services": [
            { "name": "minecraft", "port": 25565 }
        ]
    }
}
```

This is defined in the protocol but not yet integrated into the CLI.

### Identity verification

When a peer sends a `MeshHello` or `ReconnectRequest`, the receiving peer verifies that the claimed `identity` field matches the QUIC connection's transport-level identity (`conn.remote_id()`). This prevents a peer from impersonating another member by sending a forged identity in the control message.

---

## 7. TUN Device

**Module:** `src/tun.rs`

A TUN (network TUNnel) device is a virtual network interface that operates at the IP layer. Unlike a TAP device (which works at the Ethernet layer), a TUN device sends and receives raw IPv4 packets without Ethernet framing.

### Creation

The `create(v4, v6)` function takes both the peer's IPv4 and IPv6 addresses and returns `(TunReader, TunWriter, tun_name)`. Rayfish creates a TUN device with:

- **IPv4 address:** the peer's identity-derived IP (e.g., `100.64.23.142`)
- **Gateway/destination:** `100.64.0.1` (fixed for point-to-point interface on macOS)
- **IPv4 netmask:** `255.192.0.0` (/10, covering the entire CGNAT range)
- **IPv6 address:** the peer's blake3-derived address (e.g., `0200:abcd:...`) with /128 host mask
- **MTU:** 1200 bytes

The /10 netmask routes all IPv4 traffic destined for `100.64.0.0` through `100.127.255.255` to this TUN device. The IPv6 /128 address is added after device creation via platform-specific commands.

### IPv6 address assignment

The `add_ipv6_address(tun_name, addr)` function configures IPv6 on the TUN device using platform-specific commands:

- **macOS:** `ifconfig <tun> inet6 <addr> prefixlen 128`
- **Linux:** `ip -6 addr add <addr>/128 dev <tun>`

This runs after the TUN device is created and the interface name is known.

### MTU

The MTU is set to 1200 bytes, which is conservative but ensures packets fit within QUIC datagram limits. QUIC datagrams are themselves carried over UDP, which sits on top of IP. With typical path MTUs of 1280-1500 bytes, 1200 leaves comfortable room for QUIC, UDP, and IP headers without fragmentation.

### Async I/O

The TUN device is split into separate `TunReader` and `TunWriter` halves using the `tun` crate's `AsyncDevice::split()` method. This allows the read loop (outgoing packets) and write path (incoming packets) to operate concurrently without any locking.

```rust
pub struct TunReader {
    reader: DeviceReader,
}

pub struct TunWriter {
    writer: DeviceWriter,
}
```

This split/sink pattern is critical for performance — sharing an I/O device behind a Mutex serializes reads and writes, causing packet buffering and latency spikes. With separate halves, outgoing packets can be read from TUN simultaneously with incoming packets being written to TUN.

### Platform differences

**macOS (utun):** TUN devices are point-to-point interfaces that require a destination address. The `destination(100.64.0.1)` configuration satisfies this requirement.

**Linux (/dev/net/tun):** TUN devices are created through the standard Linux TUN/TAP driver. The `ensure_root_privileges(true)` platform configuration is set.

### Single TUN architecture

Rayfish uses a single TUN device per node, shared across all networks. Since all networks use the flat `100.64.0.0/10` address space and each peer has a globally unique identity-derived IP, there is no address conflict between networks. Packets are demultiplexed by looking up the destination IP in a shared routing table.

---

## 8. Packet Forwarding

**Module:** `src/forward.rs`

The forwarding module is the data plane of rayfish. It moves packets between the TUN device and peer QUIC connections.

### Architecture

Three concurrent tasks handle forwarding, with the TUN device split into separate read and write halves for lock-free I/O:

```
TunReader                     Peer connections
    |                              |
    v                              v
run_mesh()                    spawn_peer_reader() [one per peer]
  reads packets from TUN        reads datagrams from QUIC
  looks up dest IP               sends packets via tun_tx channel
  sends datagram to peer              |
                                      v
                              spawn_tun_writer(TunWriter)
                                writes packets to TUN
```

### TUN read loop (`run_mesh`)

This is the main forwarding loop. It reads packets from the TUN device in a tight loop:

1. Read a packet from TUN into a 1500-byte buffer.
2. Parse the packet header with `parse_packet_info()` — checks the version nibble to determine IPv4 or IPv6, then extracts source/destination IP, protocol, and TCP/UDP ports.
3. Dispatch on the destination address: `IpAddr::V4` calls `peers.lookup_v4()`, `IpAddr::V6` calls `peers.lookup_v6()`.
4. Check network ACL (`SharedAcl`): is this local identity allowed to send to the peer?
5. Check local firewall (`SharedFirewall`): is this outbound packet allowed by direction/protocol/port/peer rules?
6. If allowed, send the packet as a QUIC datagram on that peer's connection.
7. If denied or not found, record a dropped packet in stats.

The function takes ownership of the `TunReader` half:

```rust
pub async fn run_mesh(
    mut tun: TunReader,
    peers: PeerTable,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()>
```

### Peer readers (`spawn_peer_reader`)

Each peer connection gets a dedicated reader task that receives QUIC datagrams and forwards them to the TUN device:

1. Wait for a datagram from the peer's QUIC connection.
2. Check network ACL: is this peer allowed to send to us?
3. Check local firewall: is this inbound packet allowed by direction/protocol/port/peer rules?
4. If allowed, send the raw packet bytes through the `tun_tx` channel to the TUN writer.
5. Record received bytes in stats.

If the connection drops, the reader sends a `DisconnectEvent` (containing the peer's `EndpointId` and IP) on the disconnect channel and exits. This triggers automatic reconnection on the joiner side (see below).

### TUN writer (`spawn_tun_writer`)

A single task reads from the `tun_rx` channel and writes packets to the TUN device. This serializes writes to the TUN, avoiding concurrent access.

### Packet parsing

The `parse_packet_info()` function (in `src/firewall.rs`) handles both IPv4 and IPv6 packets by checking the version nibble (high nibble of byte 0) and dispatching to `parse_ipv4()` or `parse_ipv6()`:

**IPv4 parsing:**
- **IHL**: byte 0, low nibble gives header length in 32-bit words
- **Protocol**: byte 9 (6=TCP, 17=UDP, 1=ICMP)
- **Source IP**: bytes 12-15
- **Destination IP**: bytes 16-19
- **TCP/UDP ports**: at offset `IHL*4` (source port) and `IHL*4+2` (destination port)

**IPv6 parsing:**
- **Next Header (protocol)**: byte 6 (6=TCP, 17=UDP, 58=ICMPv6)
- **Source IP**: bytes 8-23 (16 bytes)
- **Destination IP**: bytes 24-39 (16 bytes)
- **TCP/UDP ports**: at offset 40 (fixed header length)

Returns a unified `PacketInfo` struct with `src_ip: IpAddr`, `dst_ip: IpAddr`, `protocol`, and port fields, or `None` for unrecognized or too-short packets. The forwarding loop uses `dst_ip` for routing (dispatching to the v4 or v6 DashMap) and `protocol`/`dst_port` for firewall evaluation.

### Hot-path optimizations

The forwarding path is performance-critical -- every packet traverses it. Several optimizations minimize allocations on the hot path:

- **`SmolStr` for network names**: `PeerEntry` stores the network name as a `SmolStr` (from the `smol_str` crate), which inlines strings of 23 bytes or fewer on the stack. Since network names are short, this avoids a heap allocation on every `PeerEntry` clone during lookup.
- **`Arc<AclData>` in `SharedAcl`**: The shared ACL uses `Arc` so that reading the current ACL on every packet is a refcount bump, not a deep clone of tags and rules.
- **`ArcSwap` for `SharedFirewall`**: The firewall config uses `ArcSwap` (from the `arc-swap` crate) for lock-free reads. The hot path loads the current config with a single atomic pointer swap -- no `RwLock` contention. Config updates (rare IPC operations) swap in a new `Arc<FirewallConfig>`.

---

## 9. Peer Table

**Module:** `src/peers.rs`

The `PeerTable` is the routing table that maps virtual IP addresses to QUIC connections. When the forwarding loop needs to send a packet, it looks up the destination IP here to find the right connection.

### Structure

```rust
pub struct PeerTable {
    v4: Arc<DashMap<Ipv4Addr, PeerEntry>>,
    v6: Arc<DashMap<Ipv6Addr, PeerEntry>>,
}

pub struct PeerEntry {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
    pub network: SmolStr,
}
```

The table uses dual `DashMap`s -- one keyed by IPv4, one by IPv6 -- so that the forwarding loop can look up a peer by whichever address family the packet uses. Each entry maps an IP address to:
- The QUIC `Connection` object used to send datagrams to that peer.
- The peer's `EndpointId` for identification.
- The `network` name as a `SmolStr` (inlines strings up to 23 bytes, avoiding heap allocation on clone).

### Thread safety

`DashMap` provides lock-free concurrent reads and fine-grained sharded writes without an outer `RwLock`. The `PeerTable` implements `Clone` by cloning the `Arc`s, so all clones share the same underlying data. This is how it's shared between the forwarding loop, accept loop, and mesh acceptor.

### Operations

- `add(ip, ipv6, conn, endpoint_id, network)` -- insert into both v4 and v6 maps simultaneously.
- `remove(ip)` -- remove a peer from the v4 map and return their connection.
- `lookup_v4(ip)` -- find the connection for a given IPv4 (used by the forwarding loop for IPv4 packets).
- `lookup_v6(ip)` -- find the connection for a given IPv6 (used by the forwarding loop for IPv6 packets).
- `all_connections()` -- list all peers (used for broadcasting MemberSync messages).
- `all_peer_ids()` -- list all peers with their identity strings.

### Shared across networks

In the `cmd_up` path (connecting to all saved networks), a single `PeerTable` is shared across all networks. Since the address space is flat (`100.64.0.0/10`) and each peer has a globally unique identity-derived IP, there is no ambiguity -- a given IP always maps to exactly one peer.

---

## 10. Configuration

**Module:** `src/config.rs`

Rayfish persists network memberships to `~/.config/rayfish/networks.toml` so that networks survive restarts. The daemon reads this file on startup to reconnect to all saved networks.

### File format

```toml
[[networks]]
name = "gentle-amber-fox"
group_mode = "open"
my_ip = "100.64.23.142"
network_secret_key = "deadbeef..."   # hex-encoded, only for coordinators
network_public_key = "cafebabe..."   # the join code

[[networks.members]]
identity = "abc123def456..."
ip = "100.64.10.5"
is_coordinator = true

[[networks.members]]
identity = "def456ghi789..."
ip = "100.64.23.142"
is_coordinator = false

[[networks.approved]]
identity = "jkl012abc345..."
ip = "100.64.7.99"

[[networks]]
name = "work"
group_mode = "restricted"
network_public_key = "xyz789..."
```

### Data model

**AppConfig** -- the top-level container:
```rust
pub struct AppConfig {
    pub networks: Vec<NetworkConfig>,
}
```

**NetworkConfig** -- a single network membership:
```rust
pub struct NetworkConfig {
    pub name: String,                              // local alias (three-word name)
    pub group_mode: GroupMode,                     // Open or Restricted
    pub my_ip: Option<Ipv4Addr>,                  // our IP (None if we're the coordinator)
    pub members: Vec<MemberEntry>,                 // connected members
    pub approved: Vec<ApprovedConfigEntry>,        // approved but not yet connected
    pub network_secret_key: Option<String>,        // hex-encoded, coordinators only
    pub network_public_key: Option<String>,        // the join code (public key string)
}
```

The coordinator is identified by `is_coordinator: true` in the members list. The `network_secret_key` is only present for coordinators — it's the per-network Ed25519 secret key used to sign pkarr records. The `network_public_key` is the join code shared with peers to join the network.

**MemberEntry** -- a connected member:
```rust
pub struct MemberEntry {
    pub identity: EndpointId,  // iroh public key
    pub ip: Ipv4Addr,          // identity-derived IP
    pub is_coordinator: bool,  // whether this member is the coordinator
}
```

**ApprovedConfigEntry** -- a pre-approved peer:
```rust
pub struct ApprovedConfigEntry {
    pub identity: EndpointId,  // iroh public key
    pub ip: Ipv4Addr,          // identity-derived IP
}
```

The `approved` and `membership_dht_id` fields use `#[serde(default)]`, so config files written by older versions (without these fields) still deserialize correctly.

### Coordinator vs. member

The `my_ip` field distinguishes the coordinator from members:
- **Coordinator:** `my_ip` is `None`. The coordinator doesn't need to store their own IP separately because they know it from their identity.
- **Member:** `my_ip` is `Some(ip)`. This is the IP confirmed during the join handshake.

This distinction drives `cmd_up` behavior -- coordinators start an accept loop, members connect to the coordinator.

### Operations

- `load()` -- read the config file, or return a default empty config if it doesn't exist.
- `save(config)` -- write the config to disk as pretty-printed TOML.
- `upsert_network(config, network)` -- add a network or replace an existing one with the same name.
- `remove_network(config, name)` -- remove a network by name.

### When config is written

Config is written at several points:
1. **Create:** when the coordinator creates a network (saves self as the only member, empty approved list).
2. **Join:** when a peer receives `Welcome` or `MemberSync` (saves both the member list and approved list).
3. **Accept loop:** when the coordinator approves a new peer or promotes an approved peer to member.
4. **Leave:** when the user runs `ray leave` (removes the network entry).

---

## 11. Three-Word Names

**Module:** `src/network_name.rs`

EndpointIds are 32-byte binary values, far too unwieldy to share with friends. Rayfish solves this with randomly generated three-word names in the format `adjective-noun-noun` (e.g., `gentle-amber-fox`). These names are memorable, speakable, and easy to share over chat or voice.

### Generation

`generate_name()` selects one word from each of three embedded word lists (adjectives, first-nouns, second-nouns) using a cryptographically random index:

```rust
pub fn generate_name() -> String {
    // Uses rand::random to pick indices into embedded word lists
    // Returns "adjective-noun-noun"
}
```

The word lists are embedded at compile time. The combination space is large enough that collisions are extremely rare for typical usage.

### Validation

`is_valid_name(s: &str) -> bool` checks that a string matches the three-word format (all lowercase, hyphen-separated, each word from the known lists). This is used to validate user input on `ray join`.

### Names as local aliases

Three-word names are now optional local aliases. The primary identifier for a network is its per-network public key (the join code). Names are generated at create time for human convenience and can be assigned on join with `--name`:

```bash
ray create                          # generates name + prints public key as join code
ray join <public-key> --name gaming # assigns "gaming" as a local alias
```

The join code is the network's public key string — only the coordinator (holder of the corresponding secret key) can publish records for this network, preventing MITM attacks.

---

## 12. Access Control

**Module:** `src/acl.rs`

Rayfish supports distributed, identity/tag-based ACLs. The coordinator manages allow rules that are published to all peers and enforced at the packet forwarding layer.

### Policy model

ACLs are allow-only. The semantics are simple:

- **No rules:** all traffic is allowed (open network).
- **Any rules:** only explicitly allowed traffic passes; everything else is denied.

This is an intentionally conservative model: the moment you add any rule, the default becomes deny-all.

ACLs are enforced at the forwarding layer on every peer:
- **Outbound** (`run_mesh`): packets read from the TUN device are checked before being sent to the destination peer.
- **Inbound** (`spawn_peer_reader`): packets received from peers are checked before being written to the local TUN device.

Control traffic (QUIC streams for membership, mesh hello, etc.) is always exempt — ACLs only filter data-plane packets tunneled through the TUN device.

### Tags

Tags are named labels that group peers. They enable group-based rules without listing individual endpoint IDs:

```
ray acl gentle-amber-fox tag servers ab3f... d92c...
# assigns the "servers" tag to two peers

ray acl gentle-amber-fox allow servers servers
# allow all tagged servers to reach each other
```

Targets in allow rules can be:
- A tag name (e.g., `servers`) — matches any peer with that tag
- `all` — matches any peer in the network
- An endpoint ID prefix — matches a specific peer

### CLI commands

All ACL commands are scoped to a network. Only the coordinator should modify ACLs; peers apply coordinator-published changes.

```bash
# Assign tags to peers (by endpoint ID prefix)
ray acl gentle-amber-fox tag servers ab3f... d92c...

# Remove a tag from peers
ray acl gentle-amber-fox untag servers ab3f...

# Add an allow rule: src dst
ray acl gentle-amber-fox allow servers servers
ray acl gentle-amber-fox allow all servers

# Remove a rule by index (shown in 'show' output)
ray acl gentle-amber-fox remove 0

# Show current ACL state
ray acl gentle-amber-fox show

# Re-publish the current ACL to all peers (force push)
ray acl gentle-amber-fox apply
```

### File format

ACLs are persisted to `~/.config/rayfish/acl/<network>.acl` as a plain-text file:

```
tag servers ab3f1234... d92c5678...
tag admins aa11...
allow servers -> servers
allow admins -> all
```

Lines starting with `tag` define tag assignments. Lines starting with `allow` define rules. The file is reloaded on daemon startup.

### Distribution

ACL state is included in the GroupBlob (along with members and approved list), so it's distributed as part of the single pkarr record:

1. Coordinator updates ACL, rebuilds the GroupBlob (members + approved + ACL).
2. Serializes to canonical msgpack, hashes with blake3.
3. Publishes the blob to iroh-blobs store, updates pkarr record with new hash.
4. Broadcasts a `BlobUpdated { hash }` control message to all connected peers.
5. Peers receive `BlobUpdated`, fetch the blob from any peer via iroh-blobs, verify the blake3 hash, and apply the full GroupBlob state (including the new ACL).

On join, the ACL is already part of the GroupBlob fetched from seed peers — no separate ACL fetch needed.

### Data structures

```rust
pub struct AclData {
    pub tags: Vec<TagAssignment>,   // peer → tag label mappings
    pub rules: Vec<AclRule>,        // ordered allow rules
}

pub struct TagAssignment {
    pub tag: String,
    pub peers: Vec<EndpointId>,
}

pub struct AclRule {
    pub src: AclTarget,
    pub dst: AclTarget,
}

pub enum AclTarget {
    EndpointId(EndpointId),
    Tag(String),
    All,
}
```

### Example: server network

```bash
# Tag all game servers
ray acl gaming tag servers server1... server2... server3...

# Allow all members to reach servers
ray acl gaming allow all servers

# Allow servers to reach each other (for replication)
ray acl gaming allow servers servers

# Result: regular members cannot reach each other directly —
# all traffic must go through a server
```

### The `self` keyword

When referencing peers in ACL or firewall commands, you can use the literal `self` to refer to the local device's EndpointId. This is convenient when tagging your own device:

```bash
ray acl gaming tag servers self
```

---

## 13. Local Device Firewall

**Module:** `src/firewall.rs`

The local device firewall gives each peer control over its own inbound and outbound traffic, independent of the coordinator-managed network ACL. While the network ACL is a top-down policy ("the coordinator decides who can talk to whom"), the local firewall is bottom-up ("I decide what reaches my ports").

### Policy model

Rules are evaluated **first-match-wins** with a configurable default action:

- **Default allow** (the default): all traffic passes unless explicitly denied.
- **Default deny**: all traffic is blocked unless explicitly allowed.

This is different from the network ACL (which is allow-only). The firewall supports both allow and deny rules, and the order matters — the first matching rule wins.

### Rule structure

Each rule specifies:

- **Direction**: `in` (packets arriving from peers) or `out` (packets leaving to peers)
- **Action**: `allow` or `deny`
- **Protocol**: `tcp`, `udp`, `icmp`, or `any`
- **Port**: optional port number or range (e.g., `22`, `80-443`). Applies to the destination port.
- **Peer**: optional peer identity filter. If set, the rule only matches packets from/to that specific peer.

### Packet parsing

The firewall parses both IPv4 and IPv6 packet headers to extract the protocol number and TCP/UDP port numbers. `parse_packet_info()` checks the version nibble and delegates to `parse_ipv4()` or `parse_ipv6()`. The resulting `PacketInfo` uses `IpAddr` (the Rust standard library enum) for source and destination, so firewall rules work uniformly across address families.

- **IPv4:** protocol from byte 9, ports after variable-length IP header
- **IPv6:** protocol from byte 6 (Next Header), ports after fixed 40-byte header

ICMP (protocol 1) and ICMPv6 (protocol 58) are both matched by the `icmp` protocol filter. ICMP packets have no ports, so port-based rules don't match ICMP traffic (use protocol-only rules for ICMP).

### Enforcement

The firewall is checked **after** the network ACL, in both directions:

- **Inbound** (`spawn_peer_reader`): after the network ACL allows the packet, the firewall checks direction=in, the destination port, and the sending peer's identity.
- **Outbound** (`run_mesh`): after the network ACL allows the packet, the firewall checks direction=out, the destination port, and the target peer's identity.

The `SharedFirewall` wraps an `Arc<ArcSwap<FirewallConfig>>` for lock-free reads on the hot path. Every packet checks the firewall via a single atomic load -- no lock acquisition at all. Rule changes (rare IPC operations) swap in a new `Arc<FirewallConfig>` atomically.

### CLI commands

```bash
# Show current rules and default policy
ray firewall show

# Set default policy
ray firewall default deny

# Add rules (direction action [options])
ray firewall add in allow --proto tcp --port 443
ray firewall add in allow --peer ab3f
ray firewall add out deny --proto any --peer e71a
ray firewall add in deny

# Remove a rule by index
ray firewall remove 2
```

### Persistence

Firewall rules are stored in `~/.config/rayfish/firewall.toml`:

```toml
default_action = "allow"

[[rules]]
direction = "in"
action = "deny"
protocol = "tcp"
port = "22"
peer = "any"
```

The file is loaded at daemon startup and saved on every rule change.

### Example: lock down a server

```bash
# Deny all inbound by default
ray firewall default deny

# Allow SSH from a trusted admin peer
ray firewall add in allow --proto tcp --port 22 --peer ab3f

# Allow HTTPS from anyone
ray firewall add in allow --proto tcp --port 443

# Allow all outbound
ray firewall add out allow
```

---

## 14. File Sharing

**Modules:** `src/daemon.rs` (IPC handlers, PendingFile queue), `src/control.rs` (FileOffer message), `src/transport.rs` (FILES_ALPN)

Rayfish includes peer-to-peer file sharing over the mesh. Files are content-addressed via blake3 and transferred using iroh-blobs — no cloud storage, no size limits.

### Sending a file

```bash
ray send photo.jpg alice
```

The sender reads the file, adds it to the local iroh-blobs store, resolves the peer (by hostname or short ID across all networks), connects via the dedicated `rayfish/files/1` ALPN, and sends a `FileOffer` control message containing the filename, size, MIME type (detected via `mime_guess`), and blake3 hash.

### Receiving files

The daemon's ProtocolRouter accept loop matches the FILES_ALPN and queues incoming offers as `PendingFile` entries with auto-incrementing IDs:

```bash
ray files                         # list pending offers
ray files accept 0                # accept, saves to ~/Downloads
ray files accept 0 --output .     # accept to specific directory
```

### Accept flow

On accept, the daemon connects to the sender via iroh-blobs ALPN (`/iroh-bytes/4`), fetches the blob by hash, verifies integrity (blake3), and writes to the output directory.

### Wire protocol

File offers use a dedicated ALPN (`rayfish/files/1`) separate from mesh traffic. The sender opens a bidirectional QUIC stream and sends a single `FileOffer` control message (length-prefixed msgpack). The receiver validates that the `from` field matches the connection's remote identity.

---

## 15. Magic DNS

**Modules:** `src/dns.rs`, `src/dns_config.rs`, `src/hostname.rs`

Magic DNS lets you reach peers by name instead of IP. Every peer gets a hostname — either chosen via `--hostname` at create/join time, or randomly assigned from a word list.

### Resolution scheme

Names resolve under the `.ray` TLD:

- **`alice.gaming.ray`** — fully qualified: hostname + network name
- **`alice.ray`** — flat lookup: searches all active networks, returns first match

### How it works

```
App DNS query (e.g., "alice.gaming.ray")
    |
    v
System resolver (macOS SCDynamicStore, Linux systemd-resolved D-Bus, etc.)
    |  routes only .ray queries to rayfish
    v
rayfish DNS server (UDP+TCP, 127.0.0.1:53)
    |  looks up HostnameTable + ReverseLookupTable
    v
A record (100.64.x.x) / AAAA record (200::x) / PTR record (hostname.network.ray)
```

The daemon runs a UDP+TCP DNS responder bound to `127.0.0.1:53`. It handles A (IPv4), AAAA (IPv6), PTR (reverse DNS), and SOA queries for `.ray` names. EDNS/OPT is supported (advertises 1232-byte UDP payload size). Unsupported query types on `.ray` names return NODATA (NOERROR with empty answer); queries for non-`.ray` domains return REFUSED. Queries are handled concurrently via `tokio::spawn`. A reverse lookup table (`DashMap<IpAddr, (hostname, network)>`) enables PTR resolution — `dig -x 100.64.x.x` returns `hostname.network.ray`.

### Hostname assignment

Hostnames are stored in the `Member` struct and propagated via the GroupBlob (the same mechanism used for membership and ACLs) and via MeshHello messages when peers connect. This means hostnames are available even when the named peer is offline — any peer that has fetched the blob can resolve the name.

The `HostnameTable` stores a `HostnameEntry` tuple `(Ipv4Addr, Ipv6Addr)` per hostname, keyed as `network -> hostname -> (v4, v6)`. A companion `ReverseLookupTable` (`DashMap<IpAddr, (hostname, network)>`) is maintained in parallel for PTR queries. Both tables are updated atomically via `dns::update_hostname()`.

Hostnames are persisted in `~/.config/rayfish/networks.toml` (the `my_hostname` field) so they survive daemon restarts. If no hostname is chosen and none was previously assigned, a random one is generated from a word list.

If two peers choose the same hostname, collision resolution appends a numeric suffix (e.g., `alice` → `alice2` → `alice3`).

```bash
ray create --hostname alice       # choose your hostname
ray create                        # random hostname assigned (e.g., "walrus")
ray join <key> --hostname bob     # join with a chosen hostname
```

### System DNS configuration

Rayfish configures the OS to split-route `.ray` queries to its local resolver. The detection chain (modeled on Tailscale's approach):

| Platform | Method | How |
|----------|--------|-----|
| macOS | SCDynamicStore | Writes `State:/Network/Service/rayfish/DNS` via SystemConfiguration framework with `SupplementalMatchDomains` and `SearchDomains` — session keys auto-clean on process exit |
| Linux | systemd-resolved (D-Bus) | `SetLinkDNS` + `SetLinkDomains` via `org.freedesktop.resolve1` (zbus, pure Rust) |
| Linux | NetworkManager (D-Bus) | Detects NM DNS mode, configures when NM manages DNS directly (dnsmasq/default mode) |
| Linux | systemd-resolved (CLI) | `resolvectl dns/domain` — fallback when D-Bus is unavailable |
| Linux | resolvconf | Pipes config to `resolvconf -a` — detects openresolv vs Debian variant via `resolvconf --version` |
| Linux | Direct | Prepends `nameserver 127.0.0.1` to `/etc/resolv.conf` (last resort) |

### Backup and crash recovery

On macOS, SCDynamicStore session keys are automatically removed when the process exits (clean or crash) — no backup files needed. On Linux, before modifying any DNS configuration file, rayfish saves a backup at `<path>.before-rayfish`. On daemon shutdown (clean or SIGTERM), the backup is restored. If the daemon crashes, the next startup detects stale `.before-rayfish` files and restores them before proceeding.

### Status display

`ray status` shows your hostname and peer hostnames:

```
Endpoint: ab3f...
  gentle-amber-fox [coordinator]
    Hostname: alice.gentle-amber-fox.ray
    IP: 100.64.23.142
    Peers:
      100.64.7.201 (d92c...) [bob]
```

### Constants

The DNS domain is controlled by `DNS_DOMAIN` in `src/main.rs`. Changing it from `"pi"` to something else updates all resolver paths, split-DNS routing, and query matching.

### mDNS local peer discovery

Rayfish uses `iroh-mdns-address-lookup` to advertise the daemon's endpoint on the local network via mDNS (service name `_rayfish._udp.local`). When two peers are on the same LAN, iroh automatically uses the mDNS-discovered addresses for direct connections — bypassing relay servers entirely.

mDNS is enabled by default. The setting is stored as `mdns_enabled` in `~/.config/rayfish/networks.toml` and can be toggled with `ray mdns on|off` (requires daemon restart).

On startup, the daemon builds an `MdnsAddressLookup` instance and registers it with the iroh endpoint's address lookup system. A background task logs `Discovered` and `Expired` events at INFO level. The mDNS subsystem uses its own UDP multicast sockets (via the `swarm-discovery` crate) — it is independent of iroh's transport layer and works alongside relay and Tor transports.

No changes are needed in the connect or join flow. iroh queries all registered address lookups when resolving a peer, so any peer already known through network membership will automatically get a direct LAN path if both peers are on the same network.

---

## 16. Audit Logging

**Module:** `src/audit.rs`

The audit module provides an append-only log of peer connection events at `~/.config/rayfish/audit.log`.

### Format

Each line is a tab-separated record:

```
1719835423  connect     100.64.23.142  abc123def456...
1719835430  disconnect  100.64.23.142  abc123def456...
```

Fields:
1. Unix timestamp (seconds since epoch)
2. Event type (`connect` or `disconnect`)
3. Peer's virtual IP
4. Peer's EndpointId

### Thread safety

The log file is wrapped in a `std::sync::Mutex` to allow safe concurrent writes from multiple async tasks:

```rust
pub struct AuditLog {
    file: Mutex<std::fs::File>,
}
```

Writes use `OpenOptions::append(true)`, so even if multiple processes write concurrently, individual records won't be corrupted (append writes are atomic on most filesystems for small writes).

### Current status

The audit log infrastructure is built but not yet wired into the main connection lifecycle. The API is ready:

```rust
audit.log_connect(peer_ip, &endpoint_id);
audit.log_disconnect(peer_ip, &endpoint_id);
```

---

## 17. Statistics

**Module:** `src/stats.rs`

Rayfish uses `iroh-metrics` for Prometheus-compatible metrics collection and export. The `ForwardMetrics` struct is defined with the `#[derive(MetricsGroup)]` macro and registered alongside iroh's own endpoint metrics in a shared `Registry`.

### Counters

| Counter | Meaning |
|---------|---------|
| `rayfish_packets_rx_total` | Packets received from peers |
| `rayfish_packets_tx_total` | Packets sent to peers |
| `rayfish_bytes_rx_total` | Total bytes received |
| `rayfish_bytes_tx_total` | Total bytes sent |
| `rayfish_drops_total{reason="..."}` | Dropped packets, labeled by reason |

Drop reasons: `acl` (network ACL denied), `firewall` (local firewall denied), `send_failure` (QUIC send error), `no_peer` (no route to destination), `malformed` (oversized or non-IPv4/IPv6 packet).

### Per-peer metrics

A background collector polls iroh connection stats every 60 seconds and exports per-peer gauges:

| Metric | Meaning |
|--------|---------|
| `rayfish_peer_rtt_us{peer="100.64.x.x"}` | Round-trip time in microseconds |
| `rayfish_peer_bytes_tx{peer="100.64.x.x"}` | Total bytes sent to peer (from iroh) |
| `rayfish_peer_bytes_rx{peer="100.64.x.x"}` | Total bytes received from peer (from iroh) |
| `rayfish_peer_lost_packets{peer="100.64.x.x"}` | Packets lost to peer |

These values come directly from iroh's QUIC connection stats — no manual counting needed.

### Prometheus endpoint

The daemon starts an HTTP metrics server on port 9090. Scrape it with Prometheus or curl:

```bash
curl http://localhost:9090/metrics
```

The output includes both rayfish-level metrics (`rayfish_*`) and iroh endpoint metrics (`socket_*`, `net_report_*`) in OpenMetrics text format.

### Periodic logging

The `spawn_logger` method starts a background task that logs stats every 30 seconds as deltas (not cumulative totals):

```
INFO (30s) rx=42 tx=38 bytes_rx=49356 bytes_tx=44100 drops=0
```

### CLI status

`ray status` shows aggregate traffic stats alongside per-peer connection info:

```
  Traffic: rx:142 tx:138 (98.2 KB)
```

---

## 18. Shutdown

**Module:** `src/shutdown.rs`

Rayfish uses a `CancellationToken` from `tokio-util` for coordinated shutdown. Every long-running task (forwarding loops, accept loops, peer readers, stats logger) checks this token and exits cleanly when it's cancelled.

### Signal handling

The `token()` function creates a `CancellationToken` and spawns a task that waits for a shutdown signal:

- **Unix (macOS/Linux):** listens for both `SIGINT` (Ctrl+C) and `SIGTERM`.
- **Windows:** listens for Ctrl+C only.

When the signal arrives, the token is cancelled, and all tasks that are `tokio::select!`-ing on `token.cancelled()` exit their loops and clean up.

### Shutdown flow

```
SIGINT/SIGTERM received
    |
    v
CancellationToken cancelled
    |
    +-- run_mesh() returns Ok(())
    +-- run_accept_loop() returns Ok(())
    +-- spawn_peer_reader() returns
    +-- spawn_logger() prints session summary, returns
    |
    v
main() returns
```

The shutdown is cooperative, not forceful. Each task exits at its next `tokio::select!` checkpoint, which ensures no packets are lost mid-send and all resources are released cleanly.

---

## 19. DHT Network Records

**Module:** `src/dht.rs`

Rayfish publishes network state to iroh's pkarr relay so that peers can discover each other and fetch membership/ACL data even when the coordinator is offline. A single pkarr record per network contains everything needed to join.

### Single-record model

```
  User has:  <public-key> (the join code)
                    |
                    v
  pkarr record  (keyed by network public key)
    → "v1"                          version sentinel
    → "h,<blake3_hex>"              hash of GroupBlob
    → "p,<endpoint_id>"             seed peer 1
    → "p,<endpoint_id>"             seed peer 2
    → ...
                    |
                    v
        fetch GroupBlob from any seed peer
        verify blake3 hash
        get full member + approved lists + ACL rules
```

Each network has a random Ed25519 keypair generated at create time. The public key IS the network's pkarr address and also serves as the join code. Only the coordinator (holder of the secret key) can publish or update the record.

### API

```rust
pub fn encode_network_record(key: &SecretKey, blob_hash: &str, seed_peers: &[EndpointId]) -> Result<SignedPacket>
pub fn decode_network_record(packet: &SignedPacket) -> Result<(String, Vec<EndpointId>)>
pub async fn publish_network(client, key, blob_hash, seed_peers) -> Result<()>
pub async fn resolve_network(client, network_pubkey: EndpointId) -> Result<(String, Vec<EndpointId>)>
```

The full network state (`GroupBlob`) is serialized as msgpack (sorted by identity for determinism) and stored in each peer's iroh-blobs store (`FsStore`). Every peer serves blobs via the iroh-blobs protocol ALPN. The pkarr record contains only the hash — not the data — keeping it well within DNS TXT record size limits regardless of network size.

### GroupBlob data exchange via iroh-blobs

Joiners fetch the full network state via iroh-blobs:

1. Parse the join code (public key string) → `EndpointId`.
2. Resolve the single pkarr record → `(blob_hash, seed_peers)`.
3. For each seed peer, try `try_fetch_group_blob(endpoint_id, hash)`.
4. Verify `blake3::hash(bytes) == hash` before trusting the data.
5. Deserialize `GroupBlob` to get member list, approved list, and ACL.

### Publishing

A single background task (`spawn_network_publisher`) keeps the DHT record fresh:

- Publishes immediately on startup
- Re-publishes on state changes (membership, ACL) via `tokio::sync::Notify`
- Re-publishes every 5 minutes as a periodic refresh
- Includes current online peer EndpointIds as seed peers

**Group poller** (`spawn_group_poller`):
- Checks the pkarr record for a new blob hash every 60 seconds
- If the hash changed, fetches the new GroupBlob and applies full state (members, approved, ACL)

Publishing errors are logged as warnings and never crash the coordinator or block the accept loop.

### Join resolution

When `ray join <public-key>` is run:

1. **Resolve pkarr:** look up the public key → `(blob_hash, seed_peers)`.
2. **Blob fetch:** connect to seed peers one by one until one responds. Verify hash, deserialize.
3. **Mesh join:** use member/approved lists from blob to connect to coordinator or any peer in the mesh.

### Security

The single-record model eliminates the MITM vulnerability of name-based directory lookups. The pkarr address IS the network's public key — only the holder of the corresponding secret key can publish records at that address. The pkarr relay verifies Ed25519 signatures on all publishes.

- A rogue peer cannot forge the network record without the per-network secret key.
- The join code (public key) is shared out-of-band, so an attacker can't intercept it at the DHT level.
- Peers verify the blake3 hash of the GroupBlob before trusting any data from it.
- The GroupBlob contains no secrets — the per-network secret key never leaves the coordinator's config.

---

## 20. Network Lifecycle

This chapter ties the modules together by walking through the complete lifecycle of a network.

### Creating a network

When a user runs `ray create` (optionally with `--mode open`), the CLI sends an `IpcMessage::Create` to the daemon. The daemon:

1. **Generate three-word name.** Call `network_name::generate_name()` to produce a random adjective-noun-noun name like `gentle-amber-fox`.

2. **Check not duplicate.** Verify no network with that name is already active (retry generation if needed).

3. **Create identity provider.** Wrap the public key in `IrohIdentityProvider`, which derives the coordinator's virtual IP.

4. **Generate per-network keypair.** Create a random `SecretKey` — this is the network's signing key. Its public key becomes the join code.

5. **Update ALPNs.** Call `endpoint.set_alpns()` to add `rayfish/net/<pubkey-prefix>` to the shared endpoint.

6. **Initialize membership.** Create a `MemberList` with self as the only member (marked `is_coordinator: true`). Create the membership policy based on the mode.

7. **Build and publish GroupBlob.** Serialize members + approved + ACL to canonical msgpack, hash with blake3, store in iroh-blobs. Publish single pkarr record (blob hash + self as seed peer) signed with the network secret key.

8. **Start network publisher.** Spawn `spawn_network_publisher` (single task: state changes + every 5 min).

9. **Create NetworkHandle.** Insert into the daemon's `networks` map with a child `CancellationToken`.

10. **Save config.** Write the network to `~/.config/rayfish/networks.toml` with `network_secret_key` (hex) and `network_public_key`.

11. **Return response.** Send `IpcMessage::Created` with the generated name, join code (public key), and IP back to the CLI.

### Joining a network

When a user runs `ray join <public-key> --name gaming`, the CLI sends an `IpcMessage::Join { network_key, name }` to the daemon. The daemon:

1. **Parse join code.** Parse the public key string → `EndpointId`.

2. **Resolve pkarr record.** Call `dht::resolve_network(network_pubkey)` → `(blob_hash, seed_peers)`.

3. **Fetch GroupBlob.** Try each seed peer via `try_fetch_group_blob()` until one responds. Verify the blake3 hash matches. Deserialize to get `GroupBlob` (members, approved, ACL).

4. **Update ALPNs.** Call `endpoint.set_alpns()` to add the network's ALPN.

5. **Connect to coordinator or mesh peer.** Use the member list from the blob to find a reachable peer. The first attempt goes to the coordinator. If offline, try other mesh peers.

6. **Receive welcome.** Wait for a `Welcome` message with the current member list and approved list.

7. **Check for IP collision.** The joiner checks its own derived IP against the received member list. If a different identity already occupies the same IP, the joiner bails out with an error.

8. **Connect to mesh.** For each member in the list (excluding self and the peer who sent the Welcome), open a QUIC connection and send `MeshHello`.

9. **Start tasks.** Spawn per-peer readers, reconnect loop, and group poller.

10. **Create NetworkHandle.** Insert into the daemon's `networks` map.

11. **Save config.** Write the network membership, approved list, and `network_public_key` to disk.

12. **Return response.** Send `IpcMessage::Joined` with assigned IP back to the CLI.

### Nuking a network

When a user runs `ray nuke gentle-amber-fox`, the CLI sends an `IpcMessage::Nuke { name, force }` to the daemon. The daemon:

1. **Publish empty record.** Publish a pkarr record with an empty GroupBlob hash and no seed peers. This signals to any future joiner that the network is gone.

2. **Leave network.** Cancel the per-network `CancellationToken`, wait for tasks to finish, remove peers from `PeerTable`, remove the ALPN, and delete the config entry.

The `--force` flag skips any confirmation prompt. Without it, the CLI asks the user to confirm before proceeding.

### Coordinator's accept loop

The coordinator runs continuously, accepting incoming connections. It now acts as a pure gatekeeper -- approving identities and broadcasting approvals, rather than being the sole welcome point:

1. **Accept connection.** Wait for an incoming QUIC connection with the right ALPN.

2. **Check identity.** Derive the peer's IP from their EndpointId.

3. **Case 1 -- Known member reconnecting.** If the peer is already in the member list, send them a `MemberSync` with the current member list, add them to the routing table, and spawn a reader.

4. **Case 2 -- Approved peer connecting.** If the peer is in the approved list (approved earlier but connecting now), send a `Welcome` with the member list and approved list, promote from approved to full member, broadcast `MemberSync` to all existing peers, and spawn a reader.

5. **Case 3 -- Unknown peer.** Check the `MembershipPolicy`. If not authorized, send `JoinDenied`. If authorized:
   a. **Check IP collision** against both the member list and approved list. If collision, send `JoinDenied`.
   b. **Broadcast `MemberApproved`** to all connected peers so they add the identity to their approved lists.
   c. **Immediately promote** the peer to full member (since they're already connected).
   d. **Send `Welcome`** with the member list and approved list.
   e. **Broadcast `MemberSync`** to all existing peers and spawn a reader.

### Any-peer welcome

Every peer in the mesh can welcome approved peers, not just the coordinator. The mesh acceptor handles incoming connections:

1. **Verify identity.** Check that the `MeshHello` identity matches `conn.remote_id()`.

2. **Approved peer?** If the connecting peer is in the local approved list, send a `Welcome` with the member list and approved list, promote from approved to member, and broadcast `MemberSync`.

3. **Known member?** If the peer is already a member, add them to the routing table (reconnection).

4. **Unknown peer?** Reject the connection. Unknown peers must go through the coordinator (or any authorizing peer in Open mode) first.

### Reconnecting after disconnection

Reconnection operates at two levels:

#### Per-peer reconnection (within a mesh session)

When a single peer's connection drops while the mesh is running:

1. **Detect disconnection.** The peer reader task's `conn.read_datagram()` returns an error. It sends a `DisconnectEvent` on an mpsc channel and exits.

2. **Coordinator side (`spawn_peer_cleanup`).** Receives the event and removes the dead peer from the `PeerTable`. The coordinator doesn't actively reconnect — peers reconnect to it.

3. **Joiner side (`spawn_reconnect_loop`).** Receives the event, removes the dead peer from the `PeerTable`, and spawns a per-peer reconnect task with exponential backoff (1s initial, 30s max):
   - Connects to the peer via `transport::connect_to_peer_with_alpn`
   - Sends `MeshHello` to re-establish the relationship
   - Adds the new `Connection` to the `PeerTable`
   - Spawns a fresh `spawn_peer_reader` (which feeds back into the same disconnect channel)

4. **During the gap.** The `PeerTable` has no entry for the disconnected peer's IP, so `run_mesh` silently drops packets destined for it. Once the new connection lands, traffic resumes transparently.

#### Full session reconnection (coordinator/all peers lost)

When the entire mesh session fails (e.g., `enter_mesh` returns an error):

1. **Reconnect loop.** The `cmd_join` function runs in an outer loop with exponential backoff. On disconnection, it:
   - Tries resolving membership from the DHT (if a `membership_dht_id` is saved in config) for a potentially fresher member list.
   - Tries the coordinator first.
   - If the coordinator is unavailable, tries every known peer from the saved config.
   - On successful connection, re-enters the mesh (receives MemberSync, reconnects to peers).

2. **Any peer can help.** Known peers accept reconnection requests because they hold the current member list. This is the "offline coordinator resilience" feature -- if the coordinator goes down, existing members can still reconnect to each other. DHT resolution enhances this by providing a potentially more up-to-date member list than the local config.

### Daemon startup

When the service starts the daemon (via `sudo ray up`, which runs `ray daemon`):

1. **Load identity** from `~/.config/rayfish/secret_key`.

2. **Create shared resources.** A single iroh Endpoint, TUN device, PeerTable, and Stats are created and shared across all networks.

3. **Restore saved networks** from config. For each saved network, the daemon calls its internal create or join logic to bring it back up.

4. **Start accept loop.** A shared accept loop dispatches incoming connections by ALPN to the correct network's handler.

5. **Start IPC listener.** Bind the Unix socket at `/var/run/rayfish/rayfish.sock` and accept client commands.

6. **Block on shutdown.** Wait for `CancellationToken` (SIGINT/SIGTERM or `ray down`).

All networks share the same TUN device and routing table, since the address space is flat and each peer has a globally unique IP.

---

## 21. Daemon Architecture

Rayfish uses a daemon/client split similar to Tailscale. The daemon (`ray daemon`) is a long-lived root process that owns all shared resources, while CLI commands are thin IPC clients.

### Why a daemon?

Without a daemon, each `ray create` or `ray join` was a blocking process that owned its own iroh endpoint and TUN device. There was no way to:

- Manage multiple networks from a single process
- Query live peer status
- Dynamically create, join, or leave networks at runtime

The daemon solves all three by centralizing resource ownership and accepting commands over IPC.

### Shared state (`DaemonState`)

The daemon holds:

- **`endpoint`** — a single iroh `Endpoint` shared across all networks. ALPNs are updated dynamically via `Endpoint::set_alpns()` when networks are added or removed.
- **`peers`** — a single `PeerTable` shared across all networks. Each `PeerEntry` is tagged with a network name so peers can be cleaned up per-network on leave.
- **TUN device** — a single TUN device with a /10 netmask, shared across all networks.
- **`networks`** — a `HashMap<String, NetworkHandle>` behind `RwLock`, mapping network names to their handles.
- **`shutdown_token`** — master `CancellationToken` for clean shutdown.

### Per-network state (`NetworkHandle`)

Each active network has:

- **`cancel`** — a child `CancellationToken` of the master. Cancelling it tears down only this network's tasks.
- **`tasks`** — `JoinHandle`s for the network's background tasks (DHT publisher, seed list publisher, membership poller, reconnect loop, peer cleanup).
- **`role`** — whether we're the coordinator or a member.
- **`my_ip`** — our virtual IP in this network.
- **`state`** — the `NetworkState` (member list, approved list, ACL, per-network keypair).

### IPC protocol

The Unix socket at `/var/run/rayfish/rayfish.sock` uses the same wire format as the peer-to-peer control protocol: 4-byte big-endian length prefix + msgpack body, framed via `tokio_util::codec::Framed` with a `MsgpackCodec`. A single `IpcMessage` enum carries both request and response variants:

- **Request variants** — `Create`, `Join`, `Leave`, `Nuke`, `Status`, `Shutdown`, `AclTag`, `AclUntag`, `AclAllow`, `AclRemove`, `AclShow`, `AclApply`, `FirewallAdd`, `FirewallRemove`, `FirewallShow`, `FirewallDefault`, `SetHostname`, `SendFile`, `ListFiles`, `AcceptFile`
- **Response variants** — `Ok`, `Error`, `Created` (with generated name + join code + IP), `Joined`, `StatusResponse`, `AclState`, `FirewallState`, `FileList`

The daemon accepts one connection at a time, reads a request, processes it, and sends a response. The CLI helpers (`ipc_create`, `ipc_join`, etc.) in `main.rs` handle the client side.

### Dynamic ALPN management

The key enabler for runtime network management is `Endpoint::set_alpns()`. When a network is created or joined, its ALPN (`rayfish/net/<pubkey-prefix>`) is added to the endpoint. When a network is left, the ALPN is removed. The shared accept loop dispatches incoming connections to the correct network handler based on the ALPN.

### Network teardown (`leave`)

When a network is left:

1. Cancel the per-network `CancellationToken` — stops DHT publisher, reconnect loop, and other tasks.
2. Wait for all tasks to complete.
3. Remove peers from the `PeerTable` using `remove_by_network()`.
4. Remove the `NetworkHandle` from the `networks` map.
5. Refresh ALPNs on the endpoint (removing the network's ALPN).
6. Remove the network from config.

---

## 22. Code Flow Diagrams

Visual reference for how data and control flow through the codebase.

### Coordinator startup (`ray create`)

```
create_network_inner()
  → network_name::generate_name()         adjective-noun-noun (e.g. gentle-amber-fox)
  → SecretKey::generate()                 random per-network keypair
  → IrohIdentityProvider::new()            derive virtual IP via FNV-1a
  → MemberList::new() + add(self)          first member (is_coordinator: true)
  → canonical_group_bytes() + hash         build GroupBlob, store in blob store
  → dht::publish_network(key, hash, [self]) single pkarr record
  → config::save()                         persist to networks.toml (with secret key)
     ↓
  ┌───────────────────────────────────────────────────────────────┐
  │ Background tasks:                                             │
  │                                                               │
  │  forward::spawn_tun_writer(TunWriter, tun_rx)                 │
  │    └ reads packets from channel, writes to TUN                │
  │                                                               │
  │  forward::run_mesh(TunReader, peers, ...)                      │
  │    └ reads packets from TUN, routes via PeerTable              │
  │                                                               │
  │  spawn_network_publisher(...)                                  │
  │    └ publishes pkarr record on change + every 5 min            │
  │                                                               │
  │  spawn_peer_cleanup(disconnect_rx, peers)                      │
  │    └ removes dead peers from PeerTable on disconnect          │
  └───────────────────────────────────────────────────────────────┘
     ↓
  run_accept_loop()                        blocks here
    loop {
      conn = accept_connection_with_alpn()
      remote_id = conn.remote_id()
      peer_ip = derive_ip(remote_id)

      Case 1: known member
        → send MemberSync, add to PeerTable, spawn_peer_reader

      Case 2: approved peer
        → promote to member, send Welcome, broadcast MemberSync,
          add to PeerTable, spawn_peer_reader

      Case 3: unknown peer
        → check policy → check IP collision → broadcast MemberApproved
        → add to members → send Welcome → broadcast MemberSync
        → add to PeerTable → spawn_peer_reader
    }
```

### Joiner startup (`ray join`)

```
join_network_inner("<public-key>", Some("gaming"))
  → parse public key → EndpointId
  → dht::resolve_network(network_pubkey)
      → (blob_hash, seed_peers)
         ↓
  for each seed_peer in seed_peers:        fetch GroupBlob
    try_fetch_group_blob(seed_peer, hash)
      → verify hash → deserialize GroupBlob
         ↓
  loop {                                   outer reconnect loop
    conn = connect_to_peer(coordinator_or_any_member)
         ↓
    enter_mesh(conn, ...)
      → spawn_reconnect_loop(...)          per-peer auto-reconnect
      → spawn_group_poller(...)            check pkarr hash every 60s
      → join_mesh_shared(conn, ...)
      │   ↓
      │   recv Welcome { members, approved }
      │   → config::save()                persist membership + network_public_key
      │   → peers.add(coordinator)        add to routing table
      │   → spawn_peer_reader(coordinator_conn)
      │   → for each other member:
      │       connect → send MeshHello → peers.add → spawn_peer_reader
      │   → spawn control_listener        listens for MemberApproved/MemberSync/BlobUpdated
      │   → spawn mesh_acceptor           accepts MeshHello from new peers
      │
      → forward::run_mesh(TunReader)       blocks here, forwarding packets
  }
```

### Data plane (steady state)

```
Outgoing packet (app → peer):

  App writes to 100.64.x.x or 200::x
    → kernel routes to TUN (IPv4 /10 or IPv6 /128)
    → TunReader.read_packet()              [run_mesh]
    → parse_packet_info(packet)            check version nibble (4 or 6)
    → match dst_ip:
        IpAddr::V4(v4) → peers.lookup_v4(&v4)  → Connection
        IpAddr::V6(v6) → peers.lookup_v6(&v6)  → Connection
    → conn.send_datagram(packet)           QUIC unreliable datagram

Incoming packet (peer → app):

  conn.read_datagram()                     [spawn_peer_reader, one per peer]
    → tun_tx.send(packet)                  mpsc channel
    → TunWriter.write_packet()             [spawn_tun_writer, single instance]
    → kernel delivers to app via TUN
```

### Per-peer reconnection

```
spawn_peer_reader detects conn.read_datagram() error
  → disconnect_tx.send(DisconnectEvent { endpoint_id, ip })
     ↓
  Coordinator (spawn_peer_cleanup):
    → peers.remove(ip)
    → done (peer reconnects to us)

  Joiner (spawn_reconnect_loop):
    → peers.remove(ip)
    → spawn per-peer reconnect task:
        loop {
          sleep(backoff)                   1s → 2s → 4s → ... → 30s cap
          connect_to_peer(endpoint_id)
          send MeshHello { identity, ip }
          peers.add(ip, new_conn)          transparently replaces old entry
          spawn_peer_reader(new_conn)      feeds back into disconnect_tx
          return
        }

  During gap:
    run_mesh does peers.lookup(ip) → None → packet silently dropped
  After reconnect:
    peers.lookup(ip) → new Connection → traffic resumes
```

### Task topology (per session)

```
┌─────────────────────────────────────────────────────────────┐
│ Main thread                                                  │
│  cmd_create / cmd_join / cmd_up                              │
│    → run_accept_loop (coord) or run_mesh (joiner)            │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐
│ spawn_tun_writer │  │ spawn_peer_reader│  │ spawn_peer_    │
│ (1 per session)  │  │ (1 per peer)     │  │ reader (peer B)│
│                  │  │                  │  │                │
│ tun_rx → TUN     │  │ conn → tun_tx    │  │ conn → tun_tx  │
└──────────────────┘  └──────────────────┘  └────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐
│ spawn_path_      │  │ spawn_network_   │  │ spawn_peer_    │
│ logger           │  │ publisher        │  │ cleanup /      │
│ (1 per peer)     │  │ (coord only)     │  │ reconnect_loop │
└──────────────────┘  └──────────────────┘  └────────────────┘

┌──────────────────┐
│ spawn_group_     │
│ poller           │
│ (all peers)      │
│ every 60s        │
└──────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ control_listener │  │ mesh_acceptor    │
│ (joiner only)    │  │ (joiner only)    │
│ MemberApproved,  │  │ MeshHello,       │
│ MemberSync       │  │ ReconnectRequest │
└──────────────────┘  └──────────────────┘
```

---

## 23. Security Model

### Transport security

All communication is encrypted end-to-end by iroh's QUIC implementation. Connections use TLS 1.3 with Ed25519 certificates derived from each peer's keypair. No traffic -- including relayed traffic -- can be read or modified by intermediaries.

### Identity authentication

Peers authenticate at two levels:

1. **Transport level:** The QUIC handshake verifies each peer's Ed25519 public key. A peer's `EndpointId` is cryptographically bound to their connection. You cannot connect to a peer without them proving they hold the corresponding private key.

2. **Application level:** When peers send `MeshHello` or `ReconnectRequest` messages, rayfish verifies that the claimed identity matches the transport-level identity (`conn.remote_id()`). This prevents a connected peer from claiming to be someone else.

### Membership authorization

Rayfish separates *authorization* (who can approve a new identity) from *welcome* (who can let an approved peer into the mesh):

- **Restricted mode:** Only the coordinator can authorize new members. However, once a peer is approved and the `MemberApproved` message is broadcast, *any* peer can welcome that approved identity when it connects. This means the coordinator doesn't need to be online when the approved peer actually joins -- it just needs to have been online long enough to broadcast the approval.

- **Open mode:** Any member can both authorize and welcome new peers. No coordinator involvement needed at all.

Unknown peers (not in either the member list or the approved list) are always rejected by the mesh acceptor. A peer must be explicitly approved before any node will let it in.

### Two-layer access control

Traffic filtering happens at two independent layers, both enforced at the packet forwarding level:

1. **Network ACL** (coordinator-managed): identity/tag-based allow rules distributed to all peers via GroupBlob. Controls who can talk to whom within the network. See [Section 12](#12-access-control).

2. **Local device firewall** (device-managed): per-device rules with direction, protocol, port, and peer filters. Each device controls its own firewall independently. See [Section 13](#13-local-device-firewall).

Both layers must allow a packet for it to pass. The network ACL is checked first, then the local firewall. This means a device can always restrict its own traffic further, even if the coordinator allows it.

### IP address integrity

Virtual IPs are derived from cryptographic identities, not assigned by the coordinator. Both the coordinator and the joiner verify the derivation:

1. The coordinator checks for IP collisions against the member list and approved list before broadcasting `MemberApproved`.
2. The joiner checks its own derived IP against the member list received in the `Welcome` message.

No peer can assign a different IP than what the identity hash produces. This means a peer's IP is a stable, verifiable identifier.

**IPv6 stability:** The IPv6 address is derived via blake3 into a 120-bit space (`200::/7`), making collisions practically impossible. Unlike IPv4 (which could theoretically require collision rotation via `derive_ip_with_index`), the IPv6 address is unconditionally stable -- the same identity always produces the same IPv6 address, with no rotation or suffix needed. This makes IPv6 addresses suitable as permanent, long-lived identifiers for peers.

### DHT record integrity

Each network has a single pkarr record signed by a random per-network Ed25519 secret key. The pkarr address IS the network's public key — only the coordinator (holder of the secret key) can publish or update the record. The pkarr relay verifies Ed25519 signatures on all publishes.

This eliminates the MITM vulnerability of the old name-based directory lookup (where anyone who knew the network name could derive the signing key and forge the record). The join code is the public key itself, shared out-of-band.

Peers verify the blake3 hash of the GroupBlob before trusting its contents. The GroupBlob contains no secrets — the per-network secret key never leaves the coordinator's config.

### What is NOT protected

- **Traffic analysis:** An observer on the network can see that two peers are communicating (via packet timing and size), even though they can't read the content.
- **Denial of service:** A peer can flood the network with packets. No rate limiting is currently implemented.
- **Member list confidentiality:** The member list (identities and IPs) is shared with all members. A member can see who else is in the network.
- **Reconnection window:** Packets to a disconnected peer are silently dropped until the reconnect loop establishes a new connection (up to 30 seconds with backoff).

---

## 24. Device Pairing

**Modules:** `src/identity.rs` (device certs), `src/control.rs` (PairMsg), `src/daemon.rs` (pairing handler), `src/peers.rs` (DeviceUserMap)

Rayfish's identity model normally binds one cryptographic key to one device. Device pairing extends this so that a single user can operate multiple devices under a shared identity, using certificate-based pairing.

### The problem

Without pairing, each device has its own Ed25519 keypair and its own EndpointId. If you use rayfish on a laptop and a phone, they appear as two separate peers -- different IPs, different ACL identities, different tags. You'd need to tag and authorize each device independently.

### How pairing works

Pairing creates a certificate chain: the primary device's identity key signs a certificate for each secondary device, binding the secondary's transport key to the primary's user identity.

```
Primary device (user identity key)
    |
    |-- signs DeviceCert for secondary device A
    |       binds: device_transport_key_A → user_identity
    |
    |-- signs DeviceCert for secondary device B
            binds: device_transport_key_B → user_identity
```

After pairing, all devices share the same user identity for ACL purposes, while maintaining separate transport keys for independent QUIC connections.

### Pairing flow

**On the primary device:**

```bash
ray pair
```

This generates a pairing secret, creates a pairing ticket (`bs58(endpoint_id || pairing_secret)`), and displays it as both a text string and a QR code (rendered in the terminal via `qr2term`). The daemon registers a temporary handler on the `rayfish/pair/1` ALPN to accept the incoming pairing connection.

**On the secondary device:**

```bash
ray pair <ticket>
```

The secondary daemon decodes the ticket, extracts the primary's EndpointId and the pairing secret, and connects to the primary via the PAIR_ALPN. The pairing secret authenticates the request -- only someone with the ticket can pair.

The primary verifies the secret, then signs a `DeviceCert` that binds the secondary's transport key to the primary's user identity. The signed certificate is sent back to the secondary, which stores it at `~/.config/rayfish/device_cert`.

### After pairing

When a paired device joins a network, it presents its `DeviceCert` in the MeshHello message. Receiving peers verify the certificate signature against the user identity and register a `DeviceUserMap` entry that maps the device's transport key to the user identity.

This means:
- **ACL tags** assigned to the user identity automatically cover all paired devices
- **ACL rules** referencing the user identity apply to traffic from any of the user's devices
- **IP addresses** remain per-device (each device still has its own transport key and derived IPs)
- **Connections** remain per-device (each device maintains its own QUIC connections)

The `DeviceUserMap` is consulted during ACL evaluation in the forwarding path (`forward.rs`). Before checking ACL rules, the transport key is resolved to the user identity via the map. If no mapping exists (unpaired device), the transport key is used directly as the identity, preserving backward compatibility.

### Key backup and restore

If you lose your primary device, you lose the identity key that signed all device certificates. To guard against this, rayfish supports encrypted key backup:

**Backup:**

```bash
ray pair backup
```

You are prompted for a passphrase (via `rpassword`, no terminal echo). The identity key is encrypted using chacha20poly1305 with a key derived from the passphrase via argon2. The resulting backup code is displayed for you to store securely (e.g., print it, write it down, save it in a password manager).

**Restore:**

```bash
ray pair restore <backup-code>
```

You are prompted for the passphrase. The backup code is decrypted and the identity key is restored to `~/.config/rayfish/secret_key`. After restore, the device has the same EndpointId and user identity as the original primary device.

### ACLs with paired devices

With pairing, ACL tags reference user identities rather than individual device transport keys. This simplifies multi-device management:

```bash
# Tag a user (covers all their devices)
ray acl gaming tag admins ab3f

# This rule applies to traffic from any of the user's paired devices
ray acl gaming allow admins all
```

The coordinator sees all devices of a paired user as the same identity for tagging and rule purposes. Each device still appears as a separate peer in the mesh (separate IP, separate connection), but ACL evaluation treats them as one user.

### Wire protocol

The pairing protocol uses a dedicated ALPN (`rayfish/pair/1`) and the `PairMsg` enum in `src/control.rs`:

- **PairRequest** -- sent by secondary with the pairing secret
- **PairResponse** -- sent by primary with the signed `DeviceCert` (or rejection)
- **PairComplete** -- acknowledgment from secondary

The `DeviceCert` type contains the device's transport public key, the user identity public key, and an Ed25519 signature over the binding.
