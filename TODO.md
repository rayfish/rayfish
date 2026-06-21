# Pitopi Roadmap

**Thesis:** a basic P2P layer that apps build on with zero SDK — resolve a `.pi`
name, open a socket, done. Unmodified apps work over the mesh. Priority = how directly
an item serves that socket/DNS surface.

## Done

- [x] Point-to-point tunnel between two peers
- [x] Multi-peer full mesh (N peers in one network)
- [x] Multiple simultaneous networks with isolation
- [x] Persistent network config
- [x] Three-word names for easy sharing
- [x] DHT membership publishing for offline coordinator resilience
- [x] Distributed ACLs with tag-based allow rules
- [x] Systemd/launchd service integration
- [x] Daemon architecture with Unix socket IPC
- [x] Magic DNS with .pi domain resolution (A + AAAA)
- [x] Local device firewall with port/protocol/peer filtering
- [x] Dual-stack IPv6/IPv4 with stable addresses
- [x] Tor transport via `iroh-tor-transport` (optional `--features tor`)

---

## Tier 0 — The spine (these ARE the public interface, do first)

- [x] **Refactor to iroh ProtocolHandler for ALPN dispatch**
  - MeshProtocol implements `ProtocolHandler`, one instance per network
  - ProtocolRouter dispatches by ALPN to MeshProtocol + BlobsProtocol handlers
  - Dynamic registration/unregistration as networks are created/joined/left
- [x] **Dual-stack IPv6/IPv4 with stable addresses**
  - **IPv6 (stable, identity-bound):** derived from EndpointId into `200::/7` range
    (blake3 hash, 15 bytes + `0x02` prefix → 128-bit address). Never rotates, never
    collides (120 bits of address space). TUN gets `/128` host address
  - **IPv4 (compat):** CGNAT `100.64.0.0/10` via FNV-1a. `derive_ip_with_index()`
    ready for future collision rotation (`hash(pubkey + index)`)
  - **Dual-stack forwarding:** version nibble dispatch, PeerTable with dual DashMaps
    (v4 + v6), `parse_packet_info()` handles both IPv4 and IPv6 headers
  - **DNS:** A + AAAA queries answered from `HostnameEntry = (Ipv4Addr, Ipv6Addr)`
  - **Hot-path:** SmolStr network names, Arc<AclData>, ArcSwap firewall — zero heap
    allocations and zero locks on the per-packet forwarding path
- [x] **Magic DNS**
  - Local resolver intercepts `.pi` queries → A records (IPv4) + AAAA records (IPv6)
  - Per-network names: `alice.gaming.pi`, registered on join via `--hostname`
  - Multi-platform DNS config (macOS scoped resolver, Linux systemd-resolved/resolvconf/direct)
  - Backup/restore of DNS files with crash recovery

---

## Tier 1 — Gateway features (high-bandwidth, always-on Linux peers)

These are where bulk throughput matters and where the optional WG fast path applies.

- [ ] **Subnet routing**
  - `pitopi subnet advertise 192.168.1.0/24` — expose a LAN (NAS, printer, home server)
  - Advertising peer is a gateway; routing updates propagated via control messages
  - ACL integration: which peers reach which subnets
- [ ] **Exit nodes**
  - `pitopi exit-node enable` / `pitopi exit-node use alice`
  - NAT/masquerade outbound on the exit's real interface
  - Route DNS through the exit (leak prevention) + kill switch; IPv6 from day one
  - ACL integration: who can offer / who can use
- [ ] **File sharing via iroh-blobs**
  - `pitopi send file.zip alice` — content-addressed, so dedup + resume are free
  - Lean into directory *sync*, not just one-shot send (the feature people actually want)
- [ ] **Split tunneling**
  - Route only matching traffic: `pitopi route add 10.0.0.0/8`
  - Mesh-only vs full-tunnel modes; important for gaming (game on mesh, streaming direct)
- [ ] **Kernel-WG fast path (NEW — optimization, only when throughput is measured)**
  - Scoped to easy-NAT, own-socket peers: public IP / port-mapped / full-cone / LAN
  - Tailscale-style: WG owns its own real UDP socket with GSO/GRO; iroh stays as
    control plane + fallback for hard-NAT peers
  - Prereq gates everything: port-mapping client (UPnP-IGD / NAT-PMP / PCP)
  - Linux/Windows only; macOS/iOS/Android stay on iroh (no kernel WG)
- [ ] **Multicast/broadcast relay (DEMOTED — needs per-network scoping design)**
  - Relay broadcast/multicast so LAN protocols work transparently across the mesh
  - Minecraft LAN, Steam LAN, mDNS/Bonjour discovery — friend's server shows up in LAN tab
  - Scoped per-network; rate-limited to prevent broadcast storms
  - Open question: same identity IP across all networks means source IP can't disambiguate
    which network a broadcast belongs to — relay to all networks the sender is in, or add
    an explicit scoping mechanism?

---

## Tier 2 — UX / friction reduction

- [ ] **Invite links**
  - `pitopi://join/<base58>` URI scheme handler, click-to-join anywhere
  - **Sign them** — unsigned handlers are a forgery/phishing surface
  - Optional expiry + single-use
- [ ] **Web dashboard**
  - `pitopi dashboard`, localhost only: topology, connection type, latency, per-peer stats
  - NAT-type detection, network health; add a Prometheus/OpenMetrics endpoint alongside
- [ ] **Smart relay routing (fastest-path selection)**
  - Multi-hop when faster than direct; Dijkstra/Bellman-Ford over a latency graph
  - Don't do full-mesh O(N²) pinging — gossip a sampled subset
  - Separate "opt in to relaying" from "opt in to being relayed through" (metadata privacy)

---

## Tier 3 — Protocol correctness (before public / scale)

Foundational but not blocking the MVP demo. Land before you have users who'd be hurt by bugs.

- [ ] **Identity vs node model** — user key signing device keys; affects ACLs, DNS, invites
- [ ] **Key rotation + revocation** — signed revocation lists / DHT tombstones
- [ ] **ACL merge semantics** — resolve concurrent edits (CRDT or signed monotonic log),
  not last-writer-wins
- [ ] **DHT threat model** — signed records, Sybil/eclipse/poisoning resistance, rendezvous
  fallback when the DHT degrades (this is your biggest new attack surface)

---

## Tier 4 — Hardening (DEMOTED — after the protocol stops moving)

- [ ] **Deterministic network simulator (TigerBeetle-style VOPR)**
  - Premature as a *next* item: multi-month sink to harden a committed protocol
  - For now: targeted tests for the one thing you doubt — membership/ACL convergence
    under partition — and move on
  - Full VOPR (partitions, churn, split-brain, race conditions) once the protocol is stable

---

## Tier 5 — Social product (SEPARATE PRODUCT — build ON pitopi, not IN it)

A different company with a different moat. Build at most one as a demo; defer the rest.
Discovery is centralized (Slack/Discord identity as trust anchor); once connected it's all P2P.

- [ ] Voice/calls over mesh — UDP audio + UI, as a separate binary on the public API
- [ ] Slack/Discord bot (privately hosted) — chat identity → network code, slash commands
- [ ] Open-source social connector — self-hostable generic version
- [ ] Game lobby integration — per-session networks, "click to join game night"
- [ ] Steam integration — discover networks through Steam friends/groups
- [ ] ~~SDK/API for developers~~ — mostly subsumed by sockets+DNS + the Tier 1 lifecycle API

---

## Tier 6 — Platform expansion

- [ ] macOS Network Extension (no sudo)
- [ ] BLE transport — local/offline mesh via `btleplug`, needs fragmentation layer (MTU 23-247)
- [ ] Protocol obfuscation (TCP/443, WebSocket, obfs4-style) for restrictive networks
- [ ] Windows, iOS, Android

---

## Speculative (parked)

- [ ] Post-quantum handshake (harvest-now-decrypt-later) — check iroh/noq KEM support
- [ ] Declarative signed network config ("GitOps for your mesh")
- [ ] Nym mixnet transport — high-latency privacy transport via `nym-sdk`; packets are 20KB+,
  seconds of latency, but strong metadata resistance
- [ ] I2P transport — fully decentralized alternative to Tor; `i2p-rs` ecosystem less mature
- [ ] Multipath bonding (WiFi + cellular failover) — QUIC migration gives a head start;
  a differentiator Tailscale structurally can't match
