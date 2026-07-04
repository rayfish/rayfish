# Changelog

All notable changes to Rayfish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Device ownership in `ray status`**: peer rows that are your own paired
  devices are now tagged `(your device)`, and a paired device belonging to
  another user is labelled `(user <id>)` (or shows that user's alias when you
  have set one) so it is clear which user each device belongs to. The `--json`
  output gains an `is_own_device` flag on each peer.
- **Opt-in automatic updates**: enable with `sudo ray install --auto-update` or
  `ray auto-update on`, and the daemon checks GitHub about every 6 hours for a
  newer **stable** release, then downloads, verifies (SHA-256), swaps the binary,
  and restarts itself onto the new version — no manual `sudo ray update`. Off by
  default; nightlies are never auto-installed. Applying an update restarts the
  daemon, which briefly drops the VPN (peers reconnect automatically), so it stays
  opt-in. A backoff guard means a bad release is retried at most once a day
  instead of looping. `ray status` shows when auto-update is on.
- **Auto-accept files from your own devices**: turn on
  `ray files auto-accept <network> on` (or join with
  `ray join <net> --auto-accept-files`) and incoming file transfers from your
  own paired devices land automatically in your `~/Downloads`, with no manual
  `ray files accept`. Only offers whose sender is one of your own devices (same
  paired identity) on that network are accepted; files from anyone else still
  queue for review. Turning it on also accepts any offers already waiting from
  your devices. Off by default; `ray files auto-accept <net> off` disables it.
- **Configurable auto-accept download location**: `ray files download-dir <path>`
  sends auto-accepted files to an absolute directory (owned by the dir's owner or
  `download-user`); `ray files download-user <user>` routes them to that user's
  `~/Downloads`, owned by them. With neither set, the operator's `~/Downloads` is
  used; if nothing resolves the offer stays queued rather than being written as
  root. `--clear` unsets; no argument shows the current value.
- **`ray alias <network> <key> <alias>`**: give a peer a friendly, node-local
  name. `ray alias <net> set <key> <name>` binds an alias to a user, where `key`
  is either an identity string (from `ray identityof`) or a currently-joined
  hostname. The alias then shows inline in `ray status` (as `host.net.ray
  [name]`) and seeds `ray apply`'s `aliases:` map, so a spec can reference the
  name without re-declaring it (the spec still wins on a name conflict).
  `ray alias <net> list` and `ray alias <net> rm <name>` manage the set. Aliases
  are local and display-only: they are never published to the network.
- **`ray kick <network> <peer>`**: coordinators can now remove a member from a
  closed network. Identify the peer by hostname, mesh IP, or short id. The member
  is dropped from the network's roster, and every node disconnects from it: the
  kicked peer is severed mesh-wide, not just from the coordinator. It cannot
  re-join the closed network without a fresh invite or approval (to bar it
  permanently, also revoke its invite or reusable key). Kicking is refused on open
  networks (where the peer could immediately re-join) and against another
  coordinator or yourself.
- **`ray firewall off` / `ray firewall on`**: a global switch to disable the
  userspace firewall on a device. `off` allows every mesh packet (rules and the
  secure default are bypassed; mesh membership still gates who can reach you, and
  spoofed source addresses are still dropped), for simple setups that don't want a
  second firewall layered on top of the host/kernel firewall. `on` restores
  enforcement. The disabled state is shown in `ray firewall show`.

### Changed

- **`ray firewall show` clarifies the firewall is separate from your host
  firewall**: the output now notes that this is a mesh firewall applied on top of
  your host/kernel firewall (both must allow a packet), so it is not forgotten
  when auditing an OS firewall. Enabling mesh SSH with `ray firewall ssh on` now
  reminds you to authorize a peer with `ray firewall ssh allow` when none is set
  yet (the server rejects all logins until a peer is on the allow list).
- **Bounded pending-join queue** — on a closed network, the coordinator's queue
  of join requests awaiting `ray accept` is now capped (oldest request evicted
  when full), so a peer churning fresh identities can no longer grow it without
  limit. Legitimate queues are far below the cap, so this is invisible in normal
  use.

### Performance

- **Drop-newest under datagram backpressure** — when a peer's QUIC datagram send
  buffer is momentarily full, the new packet is dropped at the application
  boundary instead of letting QUIC evict an older already-queued one (drop-newest
  beats drop-oldest for a VPN), and the QUIC transport is tuned for the one
  datagram stream per peer shape. Keeps the send path non-blocking with no
  cross-peer head-of-line blocking.

### Fixed

- **`ray status` peer traffic counters now line up**: the per-peer up/down
  columns were packed into a single field, so the `↓` counter drifted from row to
  row and the block did not read as a table. Up and down are now their own
  right-aligned columns, so the arrows and digits line up down the list.
- **`ray firewall add --peer` now accepts any peer identifier**: previously it
  only matched a short id / endpoint-id prefix, so the natural things to type
  (`--peer alice`, `--peer alice.homenet.ray`, `--peer 100.x.y.z`) failed with
  "unknown peer". It now resolves a hostname, mesh IPv4/IPv6, short id, full
  endpoint id, or a paired user identity, the same way `ray ping`, `ray send`,
  and `ray firewall ssh allow` already do. It also fixes a case where an
  **inbound** rule scoped to a paired (multi-device) peer never matched: the rule
  is now keyed on the peer's user identity, so `allow in ... --peer alice` covers
  every one of that user's devices (an outbound rule stays scoped to the named
  device).
- **Member network vanished when the coordinator was offline at startup**: a
  member (non-coordinator) whose daemon restarted while its coordinator was
  unreachable would silently drop the network from its running state. `ray
  status` showed "no active networks" and the node rejected inbound mesh
  connections, and it stayed that way until it happened to restart again while
  the coordinator was online (its config was never lost). Restore now registers
  the network immediately from the verified group blob it already holds, whether
  or not the coordinator answers, and hands off to the reconnect loop to dial the
  coordinator back with backoff. The network stays visible in `ray status`
  (peers show offline) and reconnects on its own when the coordinator returns. As
  a side effect, a network no longer takes ~30s to appear in `ray status` after a
  member restart.
- **Mesh SSH host-key mismatch**: enabling `ray firewall ssh on` no longer makes
  `ssh <host>.ray` fail with a "REMOTE HOST IDENTIFICATION HAS CHANGED" warning.
  The embedded SSH server now presents the machine's existing OpenSSH ed25519
  host key (discovered via `sshd -T`) instead of a separate generated key, so
  clients that already trust the host keep matching the fingerprint pinned in
  their `known_hosts`. Hosts without a usable OpenSSH key fall back to a
  generated key as before.

## [0.1.4]

### Added

- **Mesh SSH (`ray firewall ssh`)**: Tailscale-style SSH with no SSH keys to
  manage. `ray firewall ssh on` runs an embedded SSH server on this node's mesh
  IPs (port 22); `ray firewall ssh allow <network> <peer>` authorizes a peer
  (hostname, mesh IP, short id, or `*` for any peer on the network) to log in.
  Connect with a stock client: `ssh user@host.ray`. The connecting peer is
  identified by its mesh identity (already proven by the encrypted mesh link), so
  there are no `authorized_keys` to distribute. Each grant restricts which local
  unix users the peer may log in as: `ray firewall ssh allow <net> <peer>` permits
  any **non-root** user by default, `--user alice,deploy` limits it to named
  accounts, and `--user '*'` permits any user including root. The check is by uid,
  so a uid-0 account under any name is blocked unless root is explicitly granted.
  `ray firewall ssh deny` revokes a peer; `ray firewall ssh show` lists state and
  per-network allow lists with their permitted users. As a security prerequisite,
  inbound mesh packets whose source IP is not the sending peer's assigned mesh
  address are now dropped (ingress anti-spoofing), so no peer can forge another's
  mesh IP.
- **Aliases and groups in `ray apply`**: a spec can now define optional
  top-level `aliases:` (a friendly name to a user's identity string) and
  `groups:` (a name to a list of aliases and/or hostnames), then reference them
  as firewall subjects or peers instead of listing every hostname. An alias
  names a person and expands to all of that person's currently-joined devices;
  a group expands to the union of its members. Expansion happens client-side at
  apply time, so the published rules are plain per-host suggestions. Aliases
  resolve only for members that have already joined (a `note:` is printed and
  the rule skipped until they do); literal hostnames still work before a host
  joins. `ray apply --dry-run` shows the fully expanded result.
- **`ray identityof <net> <host>`**: print a host's identity string (the value
  to paste into a spec's `aliases:`). Resolves to the user identity if the
  device is paired, else the device's transport identity. `--json` supported.

### Fixed

- **Accepted firewall suggestions no longer pile up duplicates.** Any change to a
  network's signed blob (a join, a rename, a new reusable key) re-materialized the
  whole suggested-firewall set and re-queued it for review, even the rules this
  node had already accepted. Accepting one of those repeats via the picker then
  appended a second identical rule. Already-installed suggestions are now kept out
  of the pending queue, and the picker merges by selector (newest wins), so a
  re-suggested rule replaces its predecessor instead of stacking.
- **`ray update` no longer bricks the system service.** After swapping its own
  binary, `ray update` rewrote the service unit using the path of the running
  executable, which Linux reports with a trailing `" (deleted)"` once the old
  binary is unlinked. The unit ended up as `ExecStart=/usr/local/bin/ray (deleted)
  daemon`, so the daemon crash-looped with `unrecognized subcommand '(deleted)'`
  and the node went offline until a manual reinstall. The path is now sanitized,
  making remote self-update safe.

## [0.1.3]

### Added

- **Custom relay, discovery, and DNS-upstream servers (`ray config`)**: override
  the default iroh relay and discovery servers, or the upstream resolvers used for
  non-`.ray` queries, with `ray config set relay|discovery-dns|dns-upstreams
  <value>`. Values are a comma list of presets (`rayfish`/`n0`), URLs, or IPv4s;
  the default augments the n0 defaults, `--replace` swaps them out, and `n0`/empty
  resets. `ray config get`/`unset` read and clear overrides. Applied on
  `sudo ray restart`.
- **`ray ping <peer>`**: active mesh diagnostics: sends live echo probes to a
  peer (by hostname, mesh IP, or short id) and reports per-probe round-trip
  latency, packet loss, and whether the path is direct or relayed. `-c/--count`
  and `-i/--interval` tune the probe run; `--json` emits the per-probe array.
  Unlike `ray status` (a passive snapshot), this verifies the round-trip works
  end to end.
- **`ray netcheck`**: local network diagnostics: bound UDP port (and whether
  it is the fixed forwardable port or an ephemeral fallback), home relay and its
  latency, public IPv4/IPv6 addresses, and whether UDP is working. `--json`
  supported.
- **Release notes on `ray update`**: before swapping the binary (and in
  `ray update --check` when behind), print what the update brings: the stable
  channel walks every release in `(current, latest]` newest-first, while
  `--nightly`/`--version` show the resolved release's notes. Best-effort, so a
  fetch failure never blocks the update.
- **Standby control plane (`ray up`/`down`)**: `ray down` now takes only the
  data plane offline (TUN, routes, Magic DNS, inbound forward gate) while staying
  connected to peers, so the node keeps receiving roster/blob/firewall updates and
  `ray up` is near-instant with no re-dial. `sudo ray start`/`stop` remain the
  fully-offline switch.
- **Fail-fast firewall REJECT mode**: `ray firewall reject on|off` (opt-in,
  default off): a denied packet gets a TCP RST / ICMP-unreachable reply in both
  directions so the initiator fails immediately ("connection refused") instead of
  hanging. Off keeps the stealthy silent-drop posture.
- **`ray start` / `ray stop`** service commands to bring the whole daemon online
  or fully offline.
- **Comma-list firewall ports + short CLI aliases**: `--port`/`-P` takes a
  single port, a `start-end` range, or a comma list (`80,443`, `22,8000-9000`)
  expanded to one rule per item.
- **Control-plane abuse defense**: per-connection token-bucket rate limiting that
  closes sustained flooders, with a per-network debounced reconverge worker so a
  trigger burst coalesces into a single pkarr resolve + reconverge.

### Changed

- **Richer daemon log files**: the rolling daily logs (bundled by `ray report`)
  now capture `debug`-level detail for Rayfish itself while the console stays at
  `info`, so diagnostics like hostname propagation are traceable in a report
  without re-running with `RUST_LOG`. Dependency logs stay at `info`; `RUST_LOG`
  still overrides everything.
- **Additive firewall suggestions**: each suggested token becomes one allow/deny
  rule with no synthesized catch-all (allow-list relies on the node's own inbound
  default-deny; denies-only = blacklist). `ray status` ends with a `pending`
  summary of things awaiting the user.

### Fixed

- **`ray hostname` rename now reliably propagates.** A member's rename is kept as
  a durable pending intent and re-delivered to a coordinator on every reconnect
  and reconverge until the signed roster confirms it, so the new name reaches the
  coordinator and all peers instead of sticking only on the renamed node. The
  renamed node keeps showing its new name across reconverges rather than briefly
  reverting to the old one.
- **`ray status` no longer shows `?` for a live connection's path.** A connection
  that is up but whose path iroh hasn't marked "selected" yet (during holepunch or
  migration) now reports its actual `direct`/`relay`/`tor` path instead of `?`.
- **`ray status` no longer glues a network's `join <room-id>` onto the last peer
  row.** The room-id line now prints on its own line.
- Publish the contact record regardless of data-plane state, so `ray connect`
  resolves a peer that is on standby (`ray down`).

## [0.1.2]

### Changed

- **Magic DNS reworked to TUN interception**: `.ray` queries are intercepted in
  the TUN read loop and answered in-daemon via the magic IP `100.100.100.53`, so
  the resolver never binds the host's port 53. Non-`.ray` queries forward to the
  captured upstreams.
- **Direct-mode DNS takeover (Tailscale-style)**: on hosts without split-DNS,
  take over `/etc/resolv.conf` with an inotify re-assert loop that repairs it in
  ~ms when NetworkManager/dhclient overwrites it, plus a `dns=none` NM drop-in so
  NM stops regenerating it. Both are marker-guarded and crash-safe (panic hook +
  next-start cleanup restore the host's DNS).
- **Sharded, atomic per-network config**: globals in `settings.toml`, each
  network in `networks/<name>.toml`, all written via temp-file + atomic rename.
  Replaces the single `networks.toml` whose non-atomic rewrites raced and silently
  dropped networks; legacy files auto-migrate on first load.
- Retain only the 7 most recent daily log files.
- Authenticate GitHub API calls in `ray update` with a `gh` token (lifts the
  anonymous rate limit).

### Fixed

- Scope suggested firewall rules to non-joined networks correctly, and default a
  suggestion's peer to "any" so rules propagate instantly.
- Point systemd-resolved (`SetLinkDNS`) at the magic IP; fix the NetworkManager
  mode read on Linux.

## [0.1.1]

### Added

- **Direct connections (`ray connect`)**: link two peers with no shared room id
  or invite via a rotatable, published **contact id**. `ray connect <contact-id>`
  sends a friend request; `ray connections [approve <id>]` reviews and admits it,
  minting a 2-peer network with the requester pre-approved. `ray contact
  [id|rotate]` prints or rotates the contact key.
- **Reusable invite keys**: `ray invite <net> --reusable [--expires]` mints a
  multi-use, expiring key that rides the signed `GroupBlob`, for unattended
  fleets (`ray join <key> --hostname H --auto-accept-firewall`). Revocation
  propagates via the blob.
- **Cross-coordinator invite gossip**: single-use invites are gossiped
  (`InviteShare`/`InviteUsed`) so any coordinator can validate and burn a
  cross-minted invite; combined with dial-fallback across the published
  coordinator set, fresh joins survive any single coordinator being offline.
- **Self-update (`ray update`)**: update from GitHub releases with SHA-256
  verification and atomic binary swap; `--check`, `--list`, `--force`,
  `--nightly` (rolling pre-release), and `--version V` (pinned, downgrades
  allowed). `ray version` / `--version` print the compiled version + git SHA.
- **Stable listen port**: the shared endpoint binds a fixed UDP port (41383) so
  it survives restarts and can be manually port-forwarded for guaranteed direct
  reachability, falling back to an ephemeral port if the port is in use.
- **CLI polish**: ANSI-aligned tables, progress spinners, an interactive
  `ray firewall pending` picker, and a global `--json` flag for machine-readable
  output.
- **Per-node firewall auto-accept**: `ray join --auto-accept-firewall` /
  `ray firewall auto-accept <net> on|off` to auto-install suggested rules.
- **IPv4 collision handling**: per-member `collision_index` with `assign_ip`
  rotation, index-aware validation, duplicate-IP rejection, and a deterministic
  reconverge tiebreak.
- **Opt-in QR invites**: `ray invite --qr` prints a scannable code.

### Changed

- **Secure-by-default inbound firewall**: unsolicited inbound TCP/UDP is now
  denied by default (inbound ICMP allowed, outbound allowed), with a stateful
  conntrack letting return traffic pass. `ray firewall default allow|deny` flips
  the inbound default.
- **Removed `trusted` networks** in favor of per-device, per-network firewall
  auto-accept; coordinators suggest rules on any network and nodes consent
  per-node (auto-accept or manual `ray firewall accept`/`deny`).
- **`ray apply` is YAML-only** (previously YAML/TOML/JSON), with each network
  mapping directly to its firewall subjects.
- **Mesh ALPN is versioned as the protocol-compatibility gate**: peers on
  different mesh versions share no common ALPN and can't connect. `ray join`
  pre-checks the coordinator's signed mesh version and dials surface an
  incompatible-version hint suggesting `ray update`.
- Roster and firewall state reconverge from the network-key-signed pkarr record,
  not from peer control messages (which are payload-free triggers).

### Fixed

- **ICMP conntrack** is now echo-type-aware, closing an inbound leak where reply
  packets could be treated as solicited.
- macOS routing: assert the IPv4 `100.64.0.0/10` route on activate, and install
  a loopback self-route so you can ping your own `*.ray` IP.
- Flush control-protocol QUIC streams and the pairing device-cert response so
  messages always reach the peer before the connection drops.
- `AdminGrant` keys are self-authenticated against the network public key.

### Performance

- Zero-copy TUN read and datagram forwarding path, with Criterion microbenchmarks
  (`benches/forward.rs`) over the per-packet data path.

## [0.1.0]

First public release.

### Added

- **P2P mesh VPN** over [iroh](https://iroh.computer): peers connect by
  cryptographic identity (EndpointId), not IP. NAT traversal, hole-punching, and
  end-to-end encryption are handled by iroh, with encrypted relay fallback.
- **Dual-stack addressing** derived from identity: stable IPv4 in `100.64.0.0/10`
  (FNV-1a) and stable IPv6 in `200::/7` (blake3, 120-bit, never rotates).
- **Networks & access modes**: closed by default; `--open` for public networks.
  Closed networks admit via one-time **invite codes** (`ray invite`) or **live
  approval** (`ray requests` / `ray accept` / `ray deny`). The room id is a
  discovery key, never an admission credential.
- **Coordinator / membership model**: single signed `GroupBlob` per network
  published to a per-network pkarr record; gatekeeper admission, member roster,
  and `MemberApproved` broadcast so the coordinator need not be online for a
  member's later reconnects.
- **Co-coordinators**: `ray admin add` grants the network key over the
  authenticated mesh, enabling multiple machines to publish the signed blob.
- **Magic DNS**: reach peers at `name.network.ray` (A/AAAA/PTR/SOA), rebuilt
  from the roster on every membership change.
- **Per-device firewall**: directional, protocol-, port-, and network-scoped
  rules with a stateful conntrack; `firewall.toml`.
- **Trusted networks**: coordinators can suggest firewall rules that ride the
  signed blob; nodes auto-take (`--allow-trusted`) or queue them for manual
  `ray firewall accept` / `deny`.
- **Declarative provisioning**: `ray apply <spec>` reconciles trusted networks +
  suggested firewalls from a YAML/TOML/JSON spec, with `--prune`, `--dry-run`,
  `--invite-missing`, and `--example`.
- **Multi-device identity**: `ray pair` (ticket-based), plus encrypted
  backup/restore, including optional 1Password storage of the encrypted blob via
  the `op` CLI (`ray pair backup --1password` / `ray pair restore --1password`).
- **File sharing**: `ray send` / `ray files accept` over iroh-blobs.
- **mDNS local discovery** (`ray mdns on|off`, default on).
- **Service management**: `ray up`/`down`, `ray install`/`restart`/`uninstall`,
  and the Tailscale-style operator model (`ray set-operator`).
- **Audit log**: append-only peer connect/disconnect events at
  `~/.config/rayfish/audit.log`.
- **Diagnostics**: Prometheus metrics on `:9090`, rolling daily logs, and
  `ray report` to bundle logs + metrics + sanitized status.
- **Optional transports / export**: `--features tor` (Tor transport) and
  `--features otel` (OTLP span export).

[Unreleased]: https://github.com/rayfish/rayfish/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/rayfish/rayfish/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rayfish/rayfish/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rayfish/rayfish/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rayfish/rayfish/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rayfish/rayfish/releases/tag/v0.1.0
