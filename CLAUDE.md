# Pitopi

P2P mesh VPN powered by [iroh](https://iroh.computer). Connects peers by cryptographic identity (EndpointId), not IP address. Users create and join virtual networks with assigned IPs in the 100.64.0.0/10 (CGNAT) range.

## Build & Run

```bash
cargo -q build
cargo -q check
cargo -q test
cargo -q clippy
```

### Running

```bash
# Start the daemon (required first — owns TUN device and iroh endpoint)
sudo cargo -q run -- daemon

# In another terminal: create/join/manage networks (talks to daemon via IPC)
cargo -q run -- create --name gaming
cargo -q run -- join <room-code-or-endpoint-id> --name gaming
cargo -q run -- leave gaming
cargo -q run -- status              # live peer info from daemon
cargo -q run -- down                # shut down the daemon

# Standalone (no daemon needed)
cargo -q run -- list                # show saved networks from config

# System service
sudo cargo -q run -- install-service
sudo cargo -q run -- uninstall-service

# Shell completions
cargo -q run -- completions bash > /etc/bash_completion.d/pitopi
```

Only `daemon` (and its alias `up`) requires `sudo`. All other commands run unprivileged via IPC.

### Cross-compile & deploy

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build + install + create group + start daemon service
```

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x) → pitopi → iroh QUIC datagrams → peer
```

### Modules

- `src/main.rs` — thin CLI client (clap), IPC client functions, `spawn_path_logger`, service install/uninstall
- `src/daemon.rs` — daemon process: DaemonState (shared endpoint + TUN + PeerTable), NetworkHandle per active network, IPC server over Unix socket, coordinator accept loop, joiner mesh logic, reconnect loop, DHT publisher
- `src/ipc.rs` — IPC protocol types (IpcRequest, IpcResponse, NetworkStatus, PeerStatus), length-prefixed JSON wire helpers, socket path (`/var/run/pitopi/pitopi.sock`), client connect helper
- `src/identity.rs` — persistent Ed25519 keypair at `~/.config/pitopi/secret_key`
- `src/membership.rs` — IdentityProvider trait, FNV-1a IP derivation, MemberList, ApprovedList, GroupMode, MembershipPolicy
- `src/transport.rs` — iroh endpoint setup, per-network ALPN, connect/accept
- `src/tun.rs` — TUN device creation with /10 netmask, split into TunReader/TunWriter for lock-free I/O
- `src/forward.rs` — multi-peer forwarding: TUN → routing table → correct peer connection, DisconnectEvent notification on peer drop
- `src/dht.rs` — DHT membership publishing via iroh pkarr relay: key derivation (blake3), record encode/decode (DNS TXT), publish/resolve
- `src/control.rs` — control protocol: Welcome, MemberApproved, JoinApproved, JoinDenied, MemberSync, MeshHello, MeshWelcome, ReconnectRequest, AdvertiseServices
- `src/peers.rs` — PeerTable (routing by dest IP), PeerEntry with Connection + endpoint_id + network name, remove_by_network for teardown
- `src/config.rs` — persistent network config at `~/.config/pitopi/networks.toml` (members + approved list + membership_dht_id)
- `src/room_code.rs` — z-base-32 room codes with dashes for human-friendly sharing
- `src/acl.rs` — ACL policy engine: default policies, per-rule src/dst/port matching, packet filtering (not yet wired in)
- `src/audit.rs` — append-only audit log at `~/.config/pitopi/audit.log` (not yet wired in)
- `src/stats.rs` — packet/byte counters with periodic logging
- `src/shutdown.rs` — SIGINT/SIGTERM handling via CancellationToken

### Key flows

**Create (coordinator):** creates endpoint → derives DHT membership key → spawns DHT publisher (publishes on change + every 5 min) → listens for connections → on new peer: checks policy, checks IP collision, broadcasts MemberApproved to mesh, sends Welcome with member+approved lists+DHT ID, promotes to member, broadcasts MemberSync with DHT ID, notifies publisher.

**Join:** connects to coordinator (or any peer with approved list) → receives Welcome (member list + approved list) → joiner checks own IP for collision → creates TUN device → connects to each existing peer with MeshHello → spawns per-peer datagram readers → runs mesh forwarding loop.

**Gatekeeper model:** coordinator approves identities and broadcasts MemberApproved. Any peer can then welcome an approved identity when it connects. The coordinator doesn't need to be online when the approved peer actually joins.

**DHT membership:** coordinator derives a per-network signing key via `blake3::derive_key` from its secret key + network name. Publishes signed DNS TXT records (member/approved identities, no IPs — reconstructed via `derive_ip`) to iroh's pkarr relay (`dns.iroh.link/pkarr`). Peers learn the DHT ID from Welcome/MemberSync messages, persist it in config, and resolve it for reconnection and join fallback when the coordinator is offline. Best-effort — errors fall back to local config.

**Reconnection:** per-peer reader detects connection drop → sends DisconnectEvent on mpsc channel → coordinator side removes dead peer from PeerTable (peers reconnect to it); joiner side removes dead peer and spawns reconnect task with exponential backoff (1s–30s) → on success, sends MeshHello, adds new connection to PeerTable, spawns fresh peer reader. Packets to the peer drop silently during the gap.

**Mesh forwarding:** TUN read loop extracts dest IP from IPv4 header bytes 16-19, looks up PeerTable, sends datagram on correct connection. Per-peer reader tasks write incoming datagrams to a shared TUN writer channel.

**Network isolation:** each network gets its own ALPN (`pitopi/net/<name>`). A single shared iroh Endpoint accepts connections for all networks, filtering by ALPN on accept. Single TUN device with /10 netmask shared across networks.

**Daemon/IPC:** `pitopi daemon` starts a long-lived root process that owns the iroh Endpoint, TUN device, and PeerTable. CLI commands (`create`, `join`, `leave`, `status`, `down`) connect via Unix socket IPC (`/var/run/pitopi/pitopi.sock`) using the same length-prefixed JSON wire format as `control.rs`. The daemon uses `Endpoint::set_alpns()` to dynamically add/remove network ALPNs at runtime. Each active network gets a `NetworkHandle` with a child `CancellationToken` for clean teardown on leave.

## Key Dependencies

- `iroh` — P2P QUIC transport with NAT traversal and relay fallback
- `iroh-dns` — pkarr `SignedPacket` for DHT membership records
- `blake3` — key derivation for per-network DHT signing keys
- `tun` — cross-platform TUN device (macOS utun, Linux /dev/net/tun)
- `tokio` — async runtime
- `clap` + `clap_complete` — CLI parsing and shell completions
- `serde` + `serde_json` + `toml` — serialization for control messages and config
- `dirs` — platform config directory resolution

## Conventions

- Use `cargo -q` for all cargo commands
- Use `tracing` for logging (INFO level by default, configurable via `RUST_LOG` env var)
- ALPN per network: `pitopi/net/<name>` (e.g., `pitopi/net/gaming`)
- Virtual IPs: 100.64.0.0/10 CGNAT range — FNV-1a hash of identity, 22-bit host space
- TUN MTU: 1200 (fits within QUIC datagram limits)
- Identity persists to `~/.config/pitopi/secret_key` — same EndpointId across restarts
- Config persists to `~/.config/pitopi/networks.toml`
- macOS TUN requires destination address (point-to-point interface)
- Control messages: length-prefixed JSON (4-byte BE length + JSON body) over QUIC bidirectional streams
- Room codes: `<network_name>/<z-base-32-endpoint-id-with-dashes>`, parsed via `room_code::parse_input()`
- Use split/sink patterns for I/O — never share I/O resources (TUN, sockets, streams) behind a Mutex. Always split into separate read/write halves for concurrent access
- Avoid Mutex wherever possible — prefer channels (mpsc), split I/O, atomics, or RwLock (only for fast non-async state)
- Always update docs (CLAUDE.md, docs/book.md, README.md) after finishing a feature or significant change
