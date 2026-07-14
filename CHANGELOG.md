# Changelog

All notable changes to Rayfish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Android: keep sending and receiving files with the VPN off.** A new "Keep files
  working when the VPN is off" toggle in You (default off) keeps Rayfish's control
  plane connected when the tunnel comes down, so files still arrive and still send,
  and the phone stays visible in the mesh. Android only allows one VPN at a time, so
  this is what lets you run another VPN (Tailscale, say) and keep using Rayfish for
  files. It applies whether you turn the VPN off in the app or another VPN app takes
  the slot.
- **The install script now lives in the repo** as `install.sh`, so the one command
  users are asked to pipe into a root shell can be read, reviewed, and tested like
  the rest of the code. CI lints it and installs the latest release with it on
  Linux (glibc and musl) and macOS on every change. rayfish.xyz serves a copy of
  this file, and its CI fails if the two drift apart.

### Fixed

- **`curl -fsSL https://rayfish.xyz/install.sh | sh` works again.** The installer
  detected the host OS inside a command substitution, which runs in a subshell, so
  the value was lost in the caller and the script aborted with `OS: parameter not
  set` on every Linux and macOS host. Reported in #95, fixed by @nemanjaglumac in
  #97.

- **The installer no longer asks for `sudo` when it doesn't need it.** Pointing
  `INSTALL_DIR` at a path that didn't exist yet (`~/.local/bin`, typically) was
  treated as "not writable", so the install escalated and left a root-owned
  directory in the user's home. It now tests the nearest existing parent.

- **The installer refuses to install a binary it can't verify.** A missing `.sha256`
  sidecar silently skipped checksum verification. Every release publishes one, so a
  missing sidecar now aborts the install (`RAY_SKIP_VERIFY=1` overrides).

- **`ray mdns off` (and the other config-writing commands) now take effect on
  non-Linux hosts.** `ray mdns`, `ray auto-update`, `ray config set|unset`, and
  `ray files download-dir|download-user` wrote `settings.toml` from the CLI
  process. On Linux the config dir is a fixed `/etc/rayfish`, so this was fine, but
  on macOS/FreeBSD it is derived from the process environment: a CLI running under
  a different `HOME` than the daemon service wrote a `settings.toml` the daemon
  never read, so the setting silently reverted on restart. These commands now route
  through the daemon, which writes (and reads) its own config dir. They now require
  the daemon to be running.

- **Desktop data plane no longer wedges after an on-demand dial.** The desktop TUN
  read grew the packet pool before its `await` and truncated after, so when
  `run_mesh` cancelled the read (which it does the moment a lazy dial completes) the
  pool kept stray bytes. Every subsequent packet was then read at the wrong offset
  and parsed as garbage, silently killing all forwarding and Magic DNS until a
  restart. The read is now cancel-safe (reads into an owned buffer, commits to the
  pool only after the read returns).

- **Android: disabling the VPN now fully tears the tunnel down.** Turning the
  tunnel off dropped the mesh connection but left the VPN interface up (the key
  icon stayed and the `tun` device lingered), because the offline path closed the
  endpoint without releasing the tunnel fd. Disable now detaches the data plane
  first, so both the interface and the control plane go down and the device stops
  using the radio.

### Changed

- **Desktop TUN now runs on `tun-rs`.** Swapped the `tun` crate for `tun-rs` on
  Linux, macOS, and the other desktop targets (Android is unaffected, it uses the
  `VpnService` fd). Behavior is unchanged: same 1280 MTU, addresses and routes are
  still installed by our own netlink/`ifconfig` helpers. This is the groundwork for
  a later Linux GRO/GSO offload path that batches TUN writes.

- **FreeBSD improvements.** The logs will be stored in /var/log and the configs
  will be stored at /usr/local/etc.

### Added

- **On-demand mesh connections (near-zero idle battery).** A node connects to its
  peers at startup (so it knows immediately who is reachable), then closes any
  connection that sees no traffic in either direction for the idle timeout (default
  120s), returning to zero peer connections so it stops waking the radio for QUIC
  keepalives. The link re-forms on the next packet either side sends. Idle teardown
  coexists with older peers: a node only closes an idle link to a peer whose build
  also understands the idle close, so a peer on an earlier release is held open
  instead of flapped. On by default; turn it off with `ray config set on-demand off`
  (and `idle_timeout_secs` tunes the window).
- **`ray config` now covers the `auto-update` and `on-demand` toggles.** Both
  on/off daemon settings are settable through the standard config surface (e.g.
  `ray config set on-demand off`, `ray config set auto-update on`,
  `ray config unset on-demand`), and bare `ray config` lists their current value
  alongside relay/discovery-dns/dns-upstreams. `ray auto-update on|off` still works
  as a shorthand.
- **`ray status` shows peers as idle, active, or offline.** With on-demand
  connections a reachable peer usually has no live link, so status now renders three
  states (Tailscale-style): `active` (connected now), `idle` (a roster member with
  no current link, presumed reachable), and `offline` (only after an actual reach
  attempt failed). `ray ping <peer>` dials on demand and refreshes a peer's state.

- **Static musl Linux binaries.** Every release and nightly now also ships
  `ray-linux-{x86_64,aarch64}-musl`: fully static builds with no glibc dependency
  that run on any Linux, including musl distros (Alpine) and hosts with a glibc
  older than the gnu build floor. The installer picks them automatically when the
  glibc binary won't run on the host (and a musl asset exists for that version),
  and `ray update` on a musl-built daemon self-updates to the musl asset.

## [0.2.0] - 2026-07-08

### Changed

- **`ray status` flags peers on an incompatible mesh version.** A peer running a
  mismatched mesh protocol can't connect (the version-gated ALPN rejects it) and
  used to look like any other offline peer. Such a peer is now shown as
  `incompatible` with a `ray update` nudge, instead of plain `offline`, so it is
  clear the peer just needs updating. (Connected peers are same-version by
  definition, so this only ever applies to unreachable ones.)
- **`ray status` groups your paired devices under their user.** Devices that
  share a user identity (multi-device pairing) now nest under a parent row for
  that user showing a `N devices, M online` rollup, instead of listing flat with
  a `(user …)` tag. Standalone members are unchanged. The device columns stay
  aligned across the tree.
- **One mesh connection per peer, not per network**: peers now hold a single
  QUIC connection per device identity that carries traffic for every network they
  share, instead of one connection per shared network. A host you share two
  networks with is one connection with one round-trip estimate, so `ray status`
  and `ray ping` report the **same** RTT for it everywhere (previously each could
  read a different, sometimes-stale, per-network connection). Networks are now a
  membership/policy layer decoupled from the transport. **This is a breaking
  mesh-protocol change** — every peer must be on the new version to connect (older
  peers are cleanly severed by the protocol-version gate; run `ray update`). A
  peer kicked or removed from one shared network stays reachable on the others.
- **`ray connect` links are now symmetric**: when a direct 2-peer connection is
  approved, both peers become coordinators of the auto-created network (the
  requester is granted the network key on admission). Either side can now manage
  the link (rename, re-invite, keep it alive) instead of only the peer who
  approved it.

### Fixed

- **A flapping connection no longer evicts a valid member from the network.** A
  coordinator treated any graceful close (a `ray leave` *or* a kick) as a
  departure, so when a peer closed a link with the *kick* code (it had pruned what
  it thought was a stale roster entry, e.g. while a connection flapped), the
  coordinator wrongly dropped that member from the signed roster and republished
  without it. On a closed network the member then had to be re-admitted with `ray
  accept`, and an unstable link could repeat this indefinitely. Membership is now
  decided only by the signed record: a connection close never evicts a member and
  never makes one leave. A `ray kick` is delivered as an explicit, network-scoped
  message to the kicked member, which confirms it against the signed record and
  leaves that network (only that one) when the record confirms the removal, so a
  stale or spurious close can't evict anyone.
- **The mesh no longer tries to reach peers over their own overlay IP.** A node's
  rayfish mesh address (`100.64.0.0/10` or `200::/7`), bound on the TUN device,
  could leak into the transport addresses it advertised, so peers tried to reach
  it *through the tunnel it carries* — a self-looping path that flapped open and
  closed and could cascade into the eviction above. Those overlay ranges are now
  stripped from the addresses iroh publishes, so peers only dial real underlay
  addresses and relays.
- **`ray status` no longer lists a peer's primary device twice.** Viewed from
  another node, a user whose primary device was itself a member showed up both as
  a flat row and again as a separate group header for the same identity. The
  primary's own row (with its address and RTT) now anchors the group, and the
  paired devices nest beneath it.
- **Unpairing a device from the device itself now revokes it on the primary.** A
  secondary that unpaired itself only tore down locally; its primary kept it in
  the roster with no nullifier written, so it lingered as an offline member until
  you ran `ray unpair` on the primary. The device now asks its primary to write
  the authoritative nullifier as it leaves (best-effort, while the link is still
  up). If the device is offline from its primary at that moment, `ray unpair
  <device>` on the primary is still the way to revoke it.
- **Android no longer downgrades public DNS to cleartext.** While the VPN was up,
  non-`.ray` lookups were forwarded as plaintext UDP on port 53 to the network's
  IPv4 resolvers, ignoring any Private DNS (DoT/DoH) the device had configured.
  Rayfish now runs a small loopback proxy that forwards those lookups through the
  Android platform resolver (`DnsResolver.rawQuery`), so they honor the system
  Private DNS setting. The app is also excluded from its own tunnel so its
  sockets use the real underlying network. Devices below Android 10 (no
  `DnsResolver`) fall back to the previous plaintext behavior.
- **A reconnecting peer shows the current roster within seconds, not up to a
  minute.** After a restart a node connected to its coordinator almost instantly
  but its own `ray status` could sit on a stale roster (peers missing or shown
  offline) for ~60-90s, because it only learned the live membership from a DHT
  lookup that can serve a stale record right after boot, plus a 60s poll. A
  coordinator now hands a reconnecting member its current network-key-signed
  record directly over the mesh, so the member converges to the live roster in
  about a second. The record is still signature-verified against the network key,
  so the trust model is unchanged.
- **Leaving one network no longer disconnects you from the others you share
  with the same peer.** With one connection per peer now carrying every shared
  network, `ray leave <net>` used to tear down the whole link, cutting the peer on
  networks you never left, and if that peer coordinated one of them it could even
  drop you from its roster. Departure is now signalled in-band and scoped to the
  single network, so the rest stay up.
- **A co-coordinator renaming itself now reaches the other coordinators.**
  On a network with more than one coordinator (via `ray admin add` or a `ray
  connect` link), when one coordinator changed its own hostname the other
  coordinators never learned it: their `ray status` roster and `*.ray` DNS kept
  showing the old name. The rename now propagates to peer coordinators
  immediately, so every node converges on the new name.
- **QR scanner preview no longer appears sideways** when pairing a device on
  Android: the scanner is now pinned to portrait so the camera preview stays
  upright.

### Added

- **Desktop GUI**: `ray gui` now opens a local browser control panel with guided
  forms for status, networks, invites, firewall, files, devices, settings, and
  service actions, plus an advanced command box that runs any normal `ray`
  subcommand through the same CLI engine.
- **Unpair this device (Android)**: a paired phone can now unpair itself from the
  You screen. It leaves every network it joined, deletes its pairing certificate,
  and other peers disconnect from it right away. Re-pair from your primary device
  to rejoin. (This is the device-side counterpart to running `ray unpair` on your
  primary.)
- **Share with Rayfish (Android)**: photos, videos, and any file can now be shared
  straight to a mesh peer from the Android system share sheet. Pick an online peer
  and the file is delivered in the background (a notification confirms it was sent),
  so you are never left waiting. Sharing several items at once is supported. Files
  sent to one of your **own** paired devices are auto-accepted there and saved to
  Downloads with no tap — this is on by default and can be turned off under
  "Auto-accept from my devices" in the You screen. (Own-device is determined from
  the device pairing certificate, so a file from someone else always asks first.)
- **Ephemeral peer auto-kick**: a per-network policy that automatically removes
  members which stay offline longer than a configured time, the same as
  `ray kick`. Set it with `ray ephemeral <net> <duration>` (`12h`, `7d`, `1w`;
  minimum 1 hour), turn it off with `ray ephemeral <net> off`, and read it with
  `ray ephemeral <net> show`. Off by default; the current TTL shows on the
  network's line in `ray status`. Only the coordinator enforces it, and only
  offline peers are pruned, so it applies to open and closed networks alike (a
  removed peer can simply re-join or re-request later).
- **`ray unpair <device>`**: revoke one of your paired devices, for example a
  lost or stolen laptop. Run it from your **primary** device (the one you paired
  the others from). Revocation is **per device**: unpairing adds just that
  device's key to each affected network's signed membership record, so every peer
  rejects its certificate the moment it reconverges. Your **other** devices are
  completely untouched (no fleet-wide certificate rotation, nothing to re-issue).
  The removed device is dropped from your networks, stops being treated as one of
  your own devices (no silent auto-admit, no own-device file auto-accept), and, if
  online and cooperative, is told to leave the mesh and delete its own certificate.
  **Re-authorize later** by simply re-pairing the device: that clears the
  revocation and issues a fresh certificate. List your paired devices first with
  `ray pair list` (`--json` supported). Note: revocation currently applies to the
  networks **you coordinate**; to retire a device from a network someone else
  runs, ask that network's coordinator to remove it too.
- **Consistent Android device name**: the phone now uses one device name across
  every network instead of a different random name per network. It is seeded from
  your device model on first run and can be changed in the You screen (the change
  applies to all your networks and to any you join later).
- **Android app exclusions and mesh IPv6 on the phone**: apps that break behind a
  VPN (Android Auto, Chromecast/Google Home, RCS messaging, GoPro, Sonos) now
  bypass the tunnel, so wireless Android Auto keeps working with Rayfish on. The
  Android tunnel also routes mesh IPv6 (the `200::/7` range), which previously did
  not work on mobile.
- **Android diagnostics**: the app now captures the mesh core's recent logs and
  reports lightweight health (networks, peers online, transport, and a WARN/ERROR
  count) to crash reporting automatically when the tunnel goes up or down and when
  the connection changes between wifi and cellular. A new "Send diagnostics" button
  in the You screen attaches the full recent log to a report so connection problems
  can be diagnosed. All of this respects the existing crash-reporting toggle; the
  toggle now reads "diagnostics". Diagnostic data (the log lines and recent errors)
  can include network addresses such as relay hosts and your device's public IP, so
  it is only sent while crash reporting is on.
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
- **Auto-accept files from your own devices**: incoming file transfers from your
  own paired devices land automatically in your `~/Downloads`, with no manual
  `ray files accept`. Only offers whose sender is one of your own devices (same
  paired identity) on that network are accepted; files from anyone else still
  queue for review. This is now **on by default** (it is identity-checked, so it
  only ever accepts your own devices). Opt out for a network with
  `ray files auto-accept <net> off`, or when joining with
  `ray join <net> --no-auto-accept-files`.
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

- **Own-device file receipt is on by default**: accepting files from your own
  paired devices (identity-checked, so never anyone else) no longer needs a flag.
  New joins get it automatically; opt out with `ray join --no-auto-accept-files`
  or `ray files auto-accept <net> off`. The old `ray join --auto-accept-files`
  flag is replaced by `--no-auto-accept-files`.
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
- **Faster reconnect on startup**: when a coordinator rejoins its networks it now
  dials all known members concurrently instead of one at a time, so restore no
  longer slows down with roster size or stalls on the first unreachable peer.
- **No boot stall when a member is offline**: joining or reconnecting to a network
  no longer waits to dial the whole roster before the network comes up. A single
  unreachable member (for example a stale, offline device still on the roster)
  used to block startup for the full per-peer connection timeout, tens of seconds,
  before any other peer connected. The network is now usable as soon as the
  coordinator link is up, and the remaining peers connect concurrently in the
  background. This was most visible on the Android app as a long delay before
  peers showed online.

### Fixed

- **An unpaired device now removes itself even if it missed the live signal**: a
  device no longer relies only on the best-effort "you were unpaired" message. When
  it reconverges the signed membership record (on startup, reconnect, or the
  periodic refresh) and finds its own certificate on the deny-list, it deletes the
  certificate and leaves every network on its own. On Android this also stops the
  app from still showing the device as paired after the fact.
- **Peers now disconnect from an unpaired device right away**: after `ray unpair`
  (or a device unpairing itself), other peers could stay connected to it for a
  while. The unpaired device now tears itself out of the mesh (leaves its networks)
  as soon as it learns it was unpaired, and coordinators/members drop a revoked
  device the moment they see the updated deny-list, instead of waiting up to a
  minute for the next roster refresh.
- **Re-pairing a previously-unpaired device no longer flaps**: after unpairing and
  then re-pairing the same device, it could rapidly connect and drop over and over
  (its old key was still on your deny-list, so your primary kept rejecting the
  fresh certificate). Re-pairing now clears the device from the deny-list, so it
  reconnects cleanly and stays connected.
- **`ray status` no longer flashes "no active networks" right after a daemon
  (re)start**: the daemon began answering commands a moment before it finished
  restoring your saved networks, so a `ray status` in that window (common right
  after `ray restart` or an update) wrongly reported no networks even though they
  were intact on disk. Coordinator networks are now registered before the daemon
  accepts commands, so they show up immediately; connecting to peers still happens
  in the background.
- **QR scanner no longer opens sideways (including on foldables)**: the
  pairing/join camera scanner followed the rotation sensor and came up in
  landscape. Locking it to the launch orientation was not enough on foldables
  (Galaxy Z Fold), which report landscape at launch, so the scanner is now pinned
  to portrait outright.
- **"Send diagnostics" (Android) now reliably delivers each report**: repeat
  sends folded into a single report and the send was fire-and-forget, so a tap
  could look like it did nothing. Each report is now delivered before the "sent"
  confirmation and recorded separately.
- **Pairing no longer hangs forever when the primary is unreachable**: scanning a
  pairing code dialed the primary device with no timeout, so if it could not be
  reached (offline, no open pairing session, or an unreachable network path) the
  pairing call hung indefinitely with no feedback. It now fails within 20 seconds
  with a clear message telling you to check that the primary is online and that
  you opened pairing on it.
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

[Unreleased]: https://github.com/rayfish/rayfish/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rayfish/rayfish/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/rayfish/rayfish/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rayfish/rayfish/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rayfish/rayfish/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rayfish/rayfish/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rayfish/rayfish/releases/tag/v0.1.0
