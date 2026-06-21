# Pitopi

P2P mesh VPN powered by [iroh](https://iroh.computer). Connects peers by cryptographic identity (EndpointId), not IP address. Users create and join virtual networks with dual-stack addressing: stable IPv4 in 100.64.0.0/10 (CGNAT) and stable IPv6 in 200::/7 (blake3 hash of identity, 120-bit space, never rotates).

## Build & Run

```bash
cargo -q build
cargo -q build --features tor              # build with Tor transport support
cargo -q check
cargo -q test
cargo -q clippy
```

### Running

```bash
# Start the daemon (required first — owns TUN device and iroh endpoint)
sudo cargo -q run -- daemon

# In another terminal: create/join/manage networks (talks to daemon via IPC)
cargo -q run -- create                      # generates network + prints join code (public key)
cargo -q run -- create --name gaming        # create with a custom network name
cargo -q run -- create --hostname alice     # create with a chosen DNS hostname
cargo -q run -- join <public-key>           # join by public key (the join code)
cargo -q run -- join <public-key> --name my-net  # join with a local alias
cargo -q run -- join <public-key> --hostname bob # join with a chosen DNS hostname
cargo -q run -- create --tor                # create with Tor transport (requires tor feature + Tor daemon)
cargo -q run -- join <public-key> --tor     # join with Tor transport
cargo -q run -- leave my-net
cargo -q run -- nuke my-net                 # publish empty record + leave
cargo -q run -- hostname my-net alice        # change hostname on existing network
cargo -q run -- status              # live peer info from daemon (shows hostnames)
cargo -q run -- down                # shut down the daemon

# ACL management (coordinator only, requires daemon running)
cargo -q run -- acl my-net tag servers ab3f d92c
cargo -q run -- acl my-net untag servers ab3f
cargo -q run -- acl my-net allow servers servers
cargo -q run -- acl my-net remove 0
cargo -q run -- acl my-net show
cargo -q run -- acl my-net apply   # re-publish current ACL to peers

# Local device firewall (per-device, requires daemon running)
cargo -q run -- firewall show                              # show rules + default policy
cargo -q run -- firewall default deny                      # set default policy to deny
cargo -q run -- firewall add in allow --proto tcp --port 443  # allow inbound HTTPS
cargo -q run -- firewall add in allow --peer ab3f          # allow all from peer ab3f
cargo -q run -- firewall add out deny --peer e71a          # block outbound to peer
cargo -q run -- firewall remove 0                          # remove rule by index

# Standalone (no daemon needed)
cargo -q run -- list                # show saved networks from config

# System service
sudo cargo -q run -- install-service
sudo cargo -q run -- uninstall-service

# mDNS local peer discovery
cargo -q run -- mdns on                       # enable (default)
cargo -q run -- mdns off                      # disable

# File sharing (requires daemon running)
cargo -q run -- send photo.jpg alice          # send file to peer by hostname or short ID
cargo -q run -- files                         # list pending incoming transfers
cargo -q run -- files accept 0                # accept transfer, saves to ~/Downloads
cargo -q run -- files accept 0 --output .     # accept to current directory

# Shell completions
cargo -q run -- completions bash > /etc/bash_completion.d/pitopi
```

Only `daemon` (and its alias `up`) requires `sudo`. All other commands run unprivileged via IPC.

### Cross-compile & deploy

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build (release) + install + create group + start daemon service
just deploy-dev <ip>         # cross-build (debug) + install + start daemon service
```

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x / 200::x) → pitopi → iroh QUIC datagrams → peer
```

### Modules

- `src/main.rs` — thin CLI client (clap), IPC client functions, `spawn_path_logger`, service install/uninstall; `pitopi create [--name custom-name]` (generates network with optional custom name, prints join code), `pitopi join <public-key> [--name alias]`, `pitopi nuke <name>`, `pitopi hostname <network> <name>` (change hostname on existing network), `pitopi acl <network> tag/untag/allow/remove/show/apply` subcommands; `pitopi mdns on|off` (enable/disable mDNS local discovery, persisted to config); `pitopi send <file> <peer>` sends a file, `pitopi files` lists pending transfers, `pitopi files accept <id> [--output <dir>]` accepts a transfer; `pitopi status` displays DNS names (hostname.network.pi) instead of IPs when available + mDNS status
- `src/daemon.rs` — daemon process: DaemonState (shared endpoint + TUN + PeerTable + ProtocolRouter), NetworkHandle per active network, IPC server over Unix socket, ProtocolRouter dispatches connections via iroh ProtocolHandler by ALPN (MeshProtocol per network + BlobsProtocol for blob transfers); `CoordinatorAcceptState` and `MemberAcceptState` implement per-connection handling directly in `ProtocolHandler::accept()` via `AcceptHandler` enum — coordinator handles member auth/approval/sync, member handles MeshHello/ReconnectRequest from peers; reconnect loop, single DHT publisher (`spawn_network_publisher`), group poller (`spawn_group_poller`), local alias generation, `nuke_network()`, `restore_coordinator_network()`, ACL state on NetworkHandle, IPC handlers for ACL commands, ACL included in GroupBlob, ACL load from file on startup, empty record publish on nuke; MeshHello propagates hostname to peers with collision resolution via `resolve_collision()`, DNS table updated on peer connection; hostname persisted per-network in config (`my_hostname`); coordinator reads MeshHello from connecting peers via `spawn_coordinator_hello_reader()` to learn their hostname, update member list, and register in DNS table; joiner sends MeshHello to coordinator on initial connection; mDNS local peer discovery via `iroh-mdns-address-lookup` (advertises `_pitopi._udp.local`, enabled by default, configurable via `mdns_enabled` in AppConfig); file sharing: `PendingFile` queue on ProtocolRouter, FILES_ALPN (`pitopi/files/1`) for file offer control messages, `send_file()`/`list_files()`/`accept_file()` IPC handlers, `resolve_peer_name()` resolves hostname or short ID to EndpointId, `guess_mime_type()` via mime_guess crate
- `src/network_name.rs` — local alias generation: adjective-noun-noun word lists embedded at compile time, `generate_name()` (random selection via rand), `is_valid_name()` for validation
- `src/ipc.rs` — IPC protocol types (IpcRequest, IpcResponse, NetworkStatus, PeerStatus), length-prefixed JSON wire helpers, socket path (`/var/run/pitopi/pitopi.sock`), client connect helper; `IpcRequest::Create` has no `name` field, `IpcRequest::Join { network_key, name: Option }`, `IpcRequest::Nuke { name, force }`, `IpcRequest::AclTag`, `AclUntag`, `AclAllow`, `AclRemove`, `AclShow`, `AclApply`, `FirewallAdd`, `FirewallRemove`, `FirewallShow`, `FirewallDefault`, `SetHostname`; `IpcResponse::Created { name, network_key, my_ip, my_ipv6 }`, `IpcResponse::AclState`, `IpcResponse::FirewallState`; `NetworkStatus` includes `my_ipv6`, `PeerStatus` includes `ipv6`
- `src/identity.rs` — persistent Ed25519 keypair at `~/.config/pitopi/secret_key`
- `src/membership.rs` — IdentityProvider trait (provides both IPv4 and IPv6), FNV-1a IPv4 derivation, `derive_ipv6()` (blake3 hash into `200::/7`, 120-bit space), `derive_ip_with_index()` for collision-resistant addressing, MemberList, ApprovedList, GroupMode, MembershipPolicy, canonical msgpack serialization + blake3 hashing; `GroupBlob { members, approved, acl }`, `canonical_group_bytes()`, `group_blob_hash()`, `decode_group_blob()`, `verify_group_blob()`
- `src/transport.rs` — iroh endpoint setup, per-network ALPN, connect/accept; optional Tor transport via `iroh-tor-transport` (behind `tor` feature flag): `create_endpoint_with_alpns(key, alpns, tor)` adds `TorCustomTransport` alongside relay when `tor=true`
- `src/tun.rs` — TUN device creation with both IPv4 (/10 netmask) and IPv6 (`200::/7`) addresses, returns `(TunReader, TunWriter, String)` with tun name, `add_ipv6_address()` platform helper, split into TunReader/TunWriter for lock-free I/O
- `src/forward.rs` — multi-peer forwarding: TUN → dual-stack routing table lookup (IPv4 or IPv6) → correct peer connection, DisconnectEvent notification on peer drop; `SharedAcl` stores `Arc<AclData>` (refcount bump instead of deep clone), `SmolStr` for network keys; network ACL enforcement + local firewall enforcement in `run_mesh` (outbound: local→peer) and `spawn_peer_reader` (inbound: peer→local); labeled drop counters via `stats.record_drop(DropReason::*)`
- `src/dht.rs` — single pkarr record type per network: `encode_network_record(key, blob_hash, seed_peers)`, `decode_network_record(packet)`, `publish_network()`, `resolve_network()`; only the coordinator (holder of per-network secret key) can publish
- `src/control.rs` — length-prefixed msgpack control protocol over QUIC bidirectional streams: Welcome, MemberApproved, JoinApproved, JoinDenied, MemberSync, MeshHello, MeshWelcome, ReconnectRequest, AdvertiseServices, `BlobUpdated { hash: blake3::Hash }`; `encode_msg()`, `send_msg()`, `recv_msg()` for wire format
- `src/peers.rs` — PeerTable with dual DashMaps (v4 + v6) for routing by dest IP, `SmolStr` for network names (no heap alloc on lookup), PeerEntry with Connection + endpoint_id + network name, `lookup_v4()`/`lookup_v6()` for dual-stack routing, remove_by_network for teardown; `SharedAcl` type, `PeerTable::lookup_full()` for ACL-aware routing
- `src/config.rs` — persistent network config at `~/.config/pitopi/networks.toml` (members + approved list); `NetworkConfig` has `network_secret_key: Option<SecretKey>` (hex-serialized via custom serde adapter, coordinators only), `network_public_key: Option<EndpointId>` (the join code), and `my_hostname: Option<String>` (persisted so hostname survives daemon restarts)
- `src/acl.rs` — identity/tag-based ACL policy engine: AclData (tags + allow-only rules), rule evaluation by EndpointId with tag support, `.acl` file parser/formatter; distributed as part of GroupBlob via iroh blobs; no rules = allow-all, any rules = deny-all except explicit allows
- `src/firewall.rs` — local device firewall: per-device port/protocol/peer filtering independent of network ACL. `SharedFirewall` uses `ArcSwap` (lock-free reads) instead of `RwLock`, `PacketInfo` uses `IpAddr` for dual-stack support, `parse_packet_info()` for IPv4 and `parse_ipv6()` for IPv6 packet parsing (TCP/UDP/ICMPv6 protocol 58); first-match-wins rule evaluation; persisted to `~/.config/pitopi/firewall.toml`; enforced in `forward.rs` after network ACL checks; supports direction (in/out), protocol (tcp/udp/icmp/any), port ranges, per-peer identity filters; `self` keyword resolves to local EndpointId in ACL and firewall commands
- `src/dns.rs` — Magic DNS resolver: UDP DNS server on `127.0.0.1:53`, answers A and AAAA queries for `*.pi` names from in-memory HostnameTable (network → hostname → `HostnameEntry = (Ipv4Addr, Ipv6Addr)`), `make_aaaa_response()` for IPv6 answers, returns REFUSED for non-.pi queries; `spawn_dns_server(table, cancel)`, `HostnameTable` type, `new_hostname_table()`
- `src/dns_config.rs` — OS-level DNS configuration: `DnsConfigurator` trait with `apply()`/`revert()`, platform detection chain (macOS scoped resolver `/etc/resolver/pi`, Linux systemd-resolved/resolvconf/direct), resolver points to `127.0.0.1`, backup/restore of modified files (`.before-pitopi` suffix), crash recovery on daemon start
- `src/hostname.rs` — hostname generation (`generate_hostname()` from NOUNS_B word list), validation (`is_valid_hostname()`), collision resolution (`resolve_collision()` — appends numeric suffix, wired into MeshHello handler)
- `src/audit.rs` — append-only audit log at `~/.config/pitopi/audit.log` (not yet wired in)
- `src/stats.rs` — `ForwardMetrics` (iroh-metrics `MetricsGroup`): `packets_rx/tx`, `bytes_rx/tx` counters + `Family<DropLabels, Counter>` for labeled drops (`Acl`, `Firewall`, `SendFailure`, `NoPeer`, `Malformed`); 30-second interval logger + session summary; `PeerMetrics`: per-peer `Family<PeerLabels, Gauge>` for RTT (microseconds), bytes tx/rx, lost packets — polled every 60s from iroh connection stats; registered with iroh-metrics `Registry` alongside iroh's endpoint metrics for Prometheus export on `:9090`
- `src/shutdown.rs` — SIGINT/SIGTERM handling via CancellationToken

### Key flows

**Create (coordinator):** uses custom name if provided via `--name`, otherwise generates three-word name via `network_name::generate_name()` → generates random per-network `SecretKey` → derives dual-stack addresses (FNV-1a for IPv4, blake3 for IPv6) → builds initial `GroupBlob` (self as member, empty approved, empty ACL) → serializes + blake3 hashes → publishes blob to iroh-blobs store → publishes single pkarr record (blob hash + seed peers) signed with network secret key → persists `network_secret_key` (hex) + `network_public_key` to config → spawns `spawn_network_publisher` → prints public key as the join code.

**Join:** parses public key join code → resolves single pkarr record (blob hash + seed peers) → connects to a seed peer, fetches GroupBlob via iroh-blobs → verifies `blake3(blob) == hash` → applies members, approved list, ACL from GroupBlob → derives dual-stack addresses (IPv4 + IPv6) → connects to coordinator or mesh peer → receives Welcome (latest member list + approved list) → joiner checks own IP for collision → connects to each existing peer with MeshHello → spawns per-peer datagram readers → spawns `spawn_group_poller` to poll pkarr for blob updates.

**Nuke:** publishes pkarr record with empty GroupBlob hash + empty seed list → removes ACL file → leaves the network (tears down connections, removes from config).

**ACL management:** Coordinator uses `pitopi acl` CLI commands (tag/untag/allow/remove/show/apply) to manage identity/tag-based allow rules. Changes are persisted to `~/.config/pitopi/acl/<network>.acl`, included in the GroupBlob, serialized as canonical msgpack, hashed with blake3, published to pkarr, and broadcast to all peers via `BlobUpdated` control message. Peers fetch the blob, verify the hash, and enforce rules at the PeerTable routing layer. No rules = allow-all; any rules = deny-all except explicitly allowed traffic.

**Local firewall:** Each device has its own firewall rules (independent of coordinator-managed network ACL). Rules specify direction (in/out), action (allow/deny), protocol (tcp/udp/icmp/any), optional port or port range, and optional peer identity filter. Evaluated first-match-wins with a configurable default action (allow by default). Enforced in `forward.rs` after network ACL checks — both inbound (`spawn_peer_reader`, checks dst port) and outbound (`run_mesh`, checks dst port). Persisted to `~/.config/pitopi/firewall.toml`. Managed via `pitopi firewall` CLI commands through IPC. The `self` keyword in `resolve_short_id` resolves to the local device's EndpointId for use in both ACL and firewall commands.

**File sharing:** `pitopi send <file> <peer>` reads the file, adds it to the iroh-blobs store, resolves the peer (by hostname or short ID), connects via FILES_ALPN (`pitopi/files/1`), and sends a `FileOffer` control message (filename, size, MIME type, blake3 hash). The receiver's ProtocolRouter accept loop matches FILES_ALPN, reads the offer, and queues it as a `PendingFile` with an auto-incrementing ID. `pitopi files` lists pending offers. `pitopi files accept <id>` connects to the sender via iroh-blobs ALPN, fetches the blob by hash, verifies integrity, and writes to `~/Downloads` (or `--output <dir>`).

**Gatekeeper model:** coordinator approves identities and broadcasts MemberApproved. Any peer can then welcome an approved identity when it connects. The coordinator doesn't need to be online when the approved peer actually joins.

**DHT model (single-record):** One pkarr record per network, signed with a random per-network secret key. The record contains the GroupBlob hash and a list of online seed peers. Only the coordinator (holder of the secret key) can publish. This prevents MITM attacks — the pkarr address IS the network's public key, so the record can't be spoofed. The join code is the public key string.

A background `spawn_group_poller()` checks the pkarr record every 60s and fetches the new GroupBlob if the hash changed (reconciles members, approved list, and ACL changes).

**Reconnection:** per-peer reader detects connection drop → sends DisconnectEvent on mpsc channel → coordinator side removes dead peer from PeerTable (peers reconnect to it); joiner side removes dead peer and spawns reconnect task with exponential backoff (1s–30s) → on success, sends MeshHello, adds new connection to PeerTable, spawns fresh peer reader. Packets to the peer drop silently during the gap.

**Mesh forwarding:** TUN read loop detects IP version (v4 or v6), extracts dest address, performs dual-stack PeerTable lookup (`lookup_v4` or `lookup_v6`), sends datagram on correct connection. Per-peer reader tasks write incoming datagrams to a shared TUN writer channel.

**Network isolation:** each network gets its own ALPN (`pitopi/net/<pubkey-prefix>`, first 16 hex chars of the network public key). A single shared iroh Endpoint accepts all connections via `ProtocolRouter`, which dispatches by ALPN to per-network `MeshProtocol` handlers (each implementing iroh's `ProtocolHandler` trait). BlobsProtocol handles blob transfer connections (`/iroh-bytes/4`) through the same dispatch path. Single TUN device with /10 netmask shared across networks.

**Daemon/IPC:** `pitopi daemon` starts a long-lived root process that owns the iroh Endpoint, TUN device, PeerTable, and ProtocolRouter. CLI commands (`create`, `join`, `leave`, `nuke`, `status`, `down`) connect via Unix socket IPC (`/var/run/pitopi/pitopi.sock`) using length-prefixed JSON. The daemon uses `Endpoint::set_alpns()` to dynamically add/remove network ALPNs at runtime. Each active network registers a `MeshProtocol` handler (wrapping `CoordinatorAcceptState` or `MemberAcceptState` via `AcceptHandler` enum) with the ProtocolRouter and gets a `NetworkHandle` with a child `CancellationToken` for clean teardown on leave. `create` generates a per-network keypair and local alias; `join` accepts a public key string and resolves it via pkarr; `nuke` publishes empty record before leaving.

**Tor transport (optional):** When a network is created/joined with `--tor` (requires `tor` cargo feature), the daemon adds `TorCustomTransport` from `iroh-tor-transport` alongside the default relay transport. The Tor onion address is derived deterministically from the iroh `SecretKey` — no separate discovery needed. `TorAddressLookup` maps any `EndpointId` to its Tor address automatically. Both transports run simultaneously; iroh's path selection picks the best path (Tor has higher RTT, so relay wins when both are available; Tor is used when both peers are Tor-only). Requires a running Tor daemon: `tor --ControlPort 9051 --CookieAuthentication 0`. Transport preference is persisted per-network in config via `TransportMode`. Status display shows `[tor]` for Tor-routed connections.

**Magic DNS:** The daemon runs a UDP DNS responder on `127.0.0.1:53` that answers A and AAAA queries for `*.pi` names. Resolution scheme: `<hostname>.<network>.pi` for fully-qualified lookups, `<hostname>.pi` for flat single-network lookups. Each peer gets a hostname (random noun from word list, or user-chosen via `--hostname`). Hostnames are stored in the `Member` struct and propagated via GroupBlob. The daemon maintains an in-memory `HostnameTable` (network → hostname → `HostnameEntry` with both IPv4 and IPv6 addresses). System DNS is configured on daemon start via platform detection: macOS uses `/etc/resolver/pi` (scoped resolver), Linux tries systemd-resolved (`resolvectl domain ~pi`), resolvconf, or direct `/etc/resolv.conf` modification. All file modifications are backed up to `<path>.before-pitopi` and restored on daemon shutdown or crash recovery.

## Key Dependencies

- `iroh` — P2P QUIC transport with NAT traversal and relay fallback; `unstable-custom-transports` feature enables pluggable transport API
- `iroh-tor-transport` — (optional, `tor` feature) Tor hidden service transport for iroh; derives onion address from iroh SecretKey, handles stream-to-datagram bridging; requires running Tor daemon with `ControlPort 9051`
- `iroh-blobs` — content-addressed blob transfer for membership and ACL data exchange (FsStore, BlobsProtocol)
- `iroh-mdns-address-lookup` — mDNS local peer discovery; advertises `_pitopi._udp.local`, auto-resolves LAN peers for direct connections
- `iroh-dns` — pkarr `SignedPacket` for DHT membership records
- `blake3` — GroupBlob hashing, data integrity verification
- `hex` — encoding/decoding per-network secret keys in config
- `rand` — random local alias generation (`network_name::generate_name()`)
- `tun` — cross-platform TUN device (macOS utun, Linux /dev/net/tun)
- `tokio` — async runtime
- `clap` + `clap_complete` — CLI parsing and shell completions
- `rmp-serde` — msgpack serialization for canonical membership and ACL data (compact, deterministic)
- `serde` + `serde_json` + `toml` — serialization for control messages and config
- `simple-dns` — DNS packet parsing/building for Magic DNS resolver (A queries and responses)
- `iroh-metrics` — Prometheus-compatible metrics: `Counter`, `Gauge`, `Family` with `MetricsGroup` derive, `Registry`, `MetricsServer` HTTP endpoint
- `dashmap` — lock-free concurrent hash map for ProtocolRouter handler dispatch
- `smol_str` — inline strings for PeerTable network name keys (no heap allocation on lookup)
- `arc-swap` — lock-free atomic pointer swap for SharedFirewall (zero-cost reads on hot path)
- `humansize` — human-readable file size formatting
- `mime_guess` — extension-based MIME type detection for file sharing
- `dirs` — platform config directory resolution

## Conventions

- Use `cargo -q` for all cargo commands
- Use `tracing` for logging (INFO level by default, configurable via `RUST_LOG` env var)
- ALPN per network: `pitopi/net/<pubkey-prefix>` (first 16 hex chars of network public key)
- Virtual IPs (dual-stack): IPv4 in 100.64.0.0/10 CGNAT range (FNV-1a hash of identity, 22-bit host space) + IPv6 in 200::/7 (blake3 hash of identity, 120-bit space, stable/never rotates)
- TUN MTU: 1200 (fits within QUIC datagram limits)
- Identity persists to `~/.config/pitopi/secret_key` — same EndpointId across restarts
- Config persists to `~/.config/pitopi/networks.toml`
- ACL rules persist to `~/.config/pitopi/acl/<network>.acl` (text format: `tag <name> <peer-ids>` and `allow <src> -> <dst>` lines)
- Firewall rules persist to `~/.config/pitopi/firewall.toml` (per-device, loaded at daemon startup)
- macOS TUN requires destination address (point-to-point interface)
- Control messages: length-prefixed msgpack (4-byte BE length + msgpack body) over QUIC bidirectional streams
- Local aliases: adjective-noun-noun format (e.g., `gentle-amber-fox`), generated at create time; purely local display names with no protocol significance — the join code is the per-network public key string
- Join code: per-network public key string, printed at create time; the only way to join a network
- Use split/sink patterns for I/O — never share I/O resources (TUN, sockets, streams) behind a Mutex. Always split into separate read/write halves for concurrent access
- Avoid Mutex wherever possible — prefer channels (mpsc), split I/O, atomics, or RwLock (only for fast non-async state)
- Tor transport requires `tor` cargo feature + running Tor daemon with `ControlPort 9051`; per-network transport preference persists in `NetworkConfig.transport`
- Always update docs (CLAUDE.md, docs/book.md, README.md) after finishing a feature or significant change
