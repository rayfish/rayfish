# Rayfish

P2P mesh VPN over [iroh](https://iroh.computer). Peers are addressed by cryptographic identity (`EndpointId`), not IP. Dual-stack: stable IPv4 in `100.64.0.0/10` (FNV-1a of identity), stable IPv6 in `200::/7` (blake3, never rotates).

The crate is a library (`src/lib.rs`, daemon internals as `pub mod`) plus a thin binary (`src/main.rs`, the `ray` CLI/IPC client). The split lets benches and integration tests reach the internal data path.

The workspace also ships the mobile client: `ray-mobile` (a UniFFI cdylib wrapping the same headless daemon) and `android/` (the Kotlin/Compose app). See "Mobile" below.

> Keep this file principle-level. It documents **what holds and why**, not how every function works: the code is the source of truth for mechanics. Update it when architecture, invariants, or conventions change, not on every code edit. (The old per-module / per-flow prose lived here and drifted stale on every refactor; don't reintroduce it.)

## Build & test

```bash
cargo -q build          # --features tor (Tor transport), otel (OTLP span export)
cargo -q check          # also: clippy, test
cargo bench             # per-packet data path (benches/forward.rs)
just cross              # x86_64 Linux;  just deploy <ip> = cross-build + install + start
just apk                # ray-mobile + UniFFI Kotlin bindings + debug APK (needs cargo-ndk, JDK 17)
just android-check      # compile the Android target in a container (no NDK needed)
```

Use `cargo -q` for all cargo commands. Keep `build` / `clippy` / `test` green at every step.

## Run

The daemon (`ray daemon`) owns the TUN device + iroh endpoint and runs as a system service; the CLI talks to it over Unix-socket IPC. Full command surface + flags: `ray --help`, `ray <cmd> --help`.

Service management never calls `systemctl` directly: `init_system::InitSystem` detects systemd / OpenRC / SysV init and owns the per-init unit template (`contrib/rayfish.{service,openrc,init}`), install path, and start/stop/enable commands. macOS (launchd) is a `#[cfg]` branch at the call sites.

```bash
sudo ray up | down            # activate / standby (down keeps peer connections, drops only the data plane)
sudo ray start | stop | restart | install | uninstall | set-operator
ray create | join | leave | nuke | kick | ephemeral | hostname | status
ray invite | requests [accept|deny] | admin          # admission + coordinators
ray connect [list|approve] | contact | pair | unpair  # direct links + multi-device identity
ray firewall … | apply | alias | identityof          # policy
ray exit-node allow | disallow | use | none | status  # internet gateway (offer: Linux/macOS/BSD, use: Linux/macOS)
ray send | files | config | gui | mdns | update | ping | netcheck | logs | report
ray completions [shell] [--install]                  # tab completion (installed by `ray up`)
```

**Privilege (Tailscale operator model):** the always-root daemon does privileged work; clients are unprivileged. The IPC socket is `0666`; authority is a per-request `SO_PEERCRED` UID check (`Daemon::check_authorized`), not socket permissions. Reads are open to any local user; mutations need root or the configured `operator_uid`. Only service management (`install`/`start`/`stop`/`restart`/`uninstall`/`set-operator`/`daemon`) needs `sudo`; `up`/`down` and everything else is IPC. `ray up`/`install` auto-grant operator to `$SUDO_USER`.

## Architecture

```
App -> TUN (100.64.x.x / 200::x) -> rayfish -> iroh QUIC datagrams -> peer
```

One iroh endpoint + one TUN, shared across all networks. There is **one mesh connection per peer device** (not one per network): it carries traffic for every network the two peers share, under a single node-wide ALPN `rayfish/mesh/<version>`. The network is selected **in-band**: control frames carry `ControlFrame.net`, data datagrams carry a 2-byte network-handle tag. The `<version>` segment is the mesh protocol-version gate: peers on different versions share no ALPN and cannot connect.

The daemon (`src/daemon/`) is an **acyclic graph of `Arc` services** rooted at **`Daemon`** (the composition root: data plane, IPC dispatcher, service handles). Services own their own state and are reached by an `Arc`, so leaf tasks call them directly rather than signalling up a channel:

- **`Transport`**: endpoint, identity, blob store, metrics (the foundation everything depends on).
- **`NetworkRegistry`**: the networks map + all membership / coordinator / admission / reconverge logic (as `impl NetworkRegistry` blocks across `mesh/*.rs`).
- **`ConnectionManager`**: one QUIC connection + one id-keyed reader per peer, the frame demux, `tun_tx`.
- **`DnsService`** / **`FileService`** (`FILES_ALPN`/`PAIR_ALPN`) / **`ConnectService`** (`CONNECT_ALPN`).

### Where things live

| Area | Files |
|---|---|
| CLI + IPC client | `src/main.rs`, `src/cli/*` (tab completion: `src/cli/complete.rs`) |
| Daemon core + network ops | `src/daemon/mod.rs`, `network_registry.rs`, `mesh/*` |
| Services | `src/daemon/{foundation,connection_manager,dns_service,file_service,connect_service}.rs` |
| Wire / transport | `src/transport.rs` (ALPNs, endpoint bind), `src/control.rs` (control protocol), `src/ipc.rs` |
| Data path | `src/forward.rs` (TUN<->peer, firewall enforce, Magic-DNS intercept), `src/tun.rs`, `src/peers.rs` |
| Membership | `src/membership.rs` (GroupBlob, IP derivation), `src/invite.rs`, `src/dht.rs` (pkarr) |
| Policy | `src/firewall.rs`, `src/apply.rs`, `src/reject.rs`, `src/ssh.rs` |
| DNS | `src/dns/mod.rs` (`.ray` responder), `resolver.rs` (in-daemon resolver), `packet.rs` (UDP reply synthesis), `config.rs` (OS DNS integration) |
| Config / identity | `src/config.rs`, `src/identity.rs` |
| Misc | `src/stats.rs`, `src/ratelimit.rs`, `src/audit.rs`, `src/logdir.rs`, `src/onepassword.rs` |
| Mobile core | `ray-mobile/src/lib.rs` (UniFFI `Node`), `android_tun.rs` (VpnService fd) |
| Android app | `android/app/src/main/java/xyz/rayfish/android/` (`ui/screens/*`, `RayfishVpnService.kt`, `NodeHolder.kt`) |

## Mobile

Android runs the same core, not a reimplementation. `ray-mobile` is a UniFFI cdylib exposing a `Node` that wraps a headless `DaemonState` (`build_headless`), so create/join/pair/status/firewall all go through the desktop code path. There is no daemon process and no IPC socket on Android: Kotlin calls the `Node` directly.

- **Platform specifics stay in `ray-mobile`.** The TUN fd comes from Android's `VpnService` and is handled in `android_tun.rs`; `RustlsInit.nativeInit(context)` must run once after `System.loadLibrary` to hand the `JavaVM` + app `Context` to `ndk-context` (system DNS) and `rustls-platform-verifier` (trust store). Everything else is a thin map from the core's `IpcMessage` results to UniFFI records.
- **Same control/data plane split.** `Node::start` brings up the control plane; `Node::up` / `Node::down` attach and detach the forward loop over the VpnService fd, leaving peer connections up.
- **Bindings are generated, not written.** `android/app/src/main/java/uniffi/ray_mobile/ray_mobile.kt` is regenerated by `just apk`; never hand-edit it. Changing the UniFFI surface means regenerating and fixing the Kotlin callers in the same change. CI regenerates them too and fails on any diff, so a stale committed copy is a red build rather than something the next APK build quietly fixes.
- **UI is Compose**, one screen per tab (`HomeScreen`, `NetworksScreen`, `NetworkDetailScreen`, `YouScreen`) with shared widgets in `ui/components/Components.kt` and QR scan/render in `ui/qr/`.

## Design invariants

The rules the code upholds. Read the code for the mechanics.

- **Reachability = a shared network.** Two peers exchange packets iff they share ≥1 network (a QUIC connection only exists within one; the receiver also drops any datagram whose handle-tagged network its verified roster no longer shares with the sender). The network split is coarse access; the per-device firewall is the fine layer.
- **Room id ≠ admission.** The network public key is a discovery key, never a credential. Open networks auto-admit; closed networks gate on a one-time invite, a reusable key (carried in the signed blob), or live approval (`ray requests <net> accept`).
- **The signed `GroupBlob` is the source of truth.** One pkarr record per network, signed by the per-network key (the pkarr address *is* the public key, so records are MITM-resistant). Roster, suggested firewall, reusable keys, and `nullifiers` (`ray unpair`) all ride it. Members reconverge from the signed record on the group poll or a payload-free `MemberSync`/`BlobUpdated` **trigger**: control messages are triggers, never trusted data.
- **Coordinator = network-key holder.** Any holder can admit, suggest firewall, kick, and republish; `ray admin add` grants the key (co-coordinator). Admission survives any single coordinator being offline (the joiner dials the full coordinator set).
- **Firewall is secure-by-default.** Inbound TCP/UDP denied, inbound ICMP allowed (a seeded, removable rule), outbound allowed; a stateful conntrack lets return traffic back. Coordinator suggestions are advisory and consented per-node; local rules are never touched by reconverge.
- **Hostname authority = invite binding.** An invite-bound hostname is assigned exactly and a colliding claim is rejected; a free hostname gets suffix collision resolution. The roster is the single source of truth for `*.ray` DNS.
- **Data plane vs control plane.** The daemon connects every saved network at startup and keeps those connections for its lifetime (dropped only on leave/nuke/shutdown). `up`/`down` (`activate`/`deactivate`) toggle only the data plane (TUN link, routes, Magic DNS, forward gate); `start`/`stop` toggle the whole process.
- **IPv6-only is a start-time mode.** `ipv6_only` (for sharing a host with a VPN that owns `100.64.0.0/10`) is read once at startup because the TUN's addressing is fixed when the device is created. The derived IPv4 is still assigned, as a `/32` instead of a `/10` (only the connected route collides), because it stays the node's internal handle: peer table, roster, and status all key on it. Magic DNS moves to `MAGIC_DNS_V6` (`200::53`, already covered by the `200::/7` route) in this mode. **The v4 magic IP is not merely redundant there, it is broken:** Tailscale installs `-s 100.64.0.0/10 ! -i tailscale0 -j DROP`, and our reply is synthesized *from* the magic IP *into* the TUN, so netfilter eats it and `.ray` silently times out. Routing is not the only thing that can stop a packet. **Where the mode comes from is per-platform, but it is decided at build time either way:** desktop reads `settings.toml`, embedders pass it as an argument (`build_headless_with_setting(on_demand, ipv6_only)`), because on Android the config dir is app-private and the user's choice lives in the app's own preferences. Changing it there means building a new daemon, and a new tunnel with it (`ACTION_RESTART_NODE`).
- **The setting is three-valued, and so is what it resolves to.** One enum carries both: `Ipv6Only::{Auto, On, Off}` (`ray-proto`), the setting in `settings.toml` and the app's own store, and the mode `ray status` reports. On `auto` the startup scan decides: something else already on `100.64.0.0/10` means start IPv6-only, so the node runs rather than refusing. `off` is the standing refusal, and it is why the setting cannot be a bool: it has to be sayable, or a host could not opt out of being moved. As a *reported* mode `Auto` is not undecided, it means on and chosen by the scan, which is why one type serves both ends and why nothing carries a second `auto` flag beside a bool. An auto decision is **never written back** (the mode follows the host and ends when the other VPN does), so it travels through `Overrides`, not the config, and `Ipv6Only::enabled()` is what the data path asks. Old configs said `ipv6_only = true`, so the deserializer still takes a bool. `decide_ipv6_only` holds the table and `resolve_ipv6_only` applies it on both platforms, over netlink/`ifconfig` on desktop and `getifaddrs` on Android, where the scan also has to skip our own mesh IPv4: the `VpnService` interface can already be up when the node is rebuilt, and counting our own address as a conflict would latch the mode on for good. Embedders that have already decided call `build_headless`; those holding the tri-state call `build_headless_with_setting`, which is the only one that scans (so tests never do).
- **Two separate facts drive DNS answers, and both are needed.** *This node* cannot use mesh v4 (a flag on `Resolver`, so even a dual-stack peer is not offered an A record here), and *that peer* cannot (`Member.ipv6_only` on the signed roster, carried into `HostnameEntry`'s `Option<Ipv4Addr>`). Withheld A records are NODATA, never NXDOMAIN, which would fail the AAAA alongside them.
- **The daemon resolves its own names, and never through itself.** The endpoint is built with an explicit `DnsResolver` (`transport::control_plane_nameservers`): configured `dns_upstreams`, then the host's resolvers as read before any takeover, then a public server. iroh's default reads `/etc/resolv.conf` once at bind, which is a circle and a single point of failure at the same time — the file may already name our magic IP (a restart before the revert), and a host whose only nameserver stopped answering took the whole control plane down with it, relay and pkarr included (#111). The list is the daemon's own, only ever asked for the relay and the discovery server, and the overlay filter is what keeps the magic IP out of it. `None` from `system_nameservers` means *unreadable here* (Android keeps them behind JNI), not *none*: that host keeps iroh's reader, since pinning it to a public server would step over the device's Private DNS.
- **The outbound network tag comes from what the peer acknowledges.** A datagram is stamped with a network handle and the receiver drops it unless it shares that network (`resolve_inbound_by_id`), so the sender's pick has to agree with the receiver's view or the peer is black-holed. Our shared set is not that view: a peer that leaves a network without being able to say so stays in ours for good when we hold the network, since our own roster is the record nothing corrects. `PeerEntry::route` therefore picks from the networks the peer announced handles for (`in_handles`, its own statement, already on the wire), falling back to the plain pick only before the announcement lands. Names keep resolving from the stale roster either way, which is why the failure reads as "the mesh is up and the connection times out".
- **Reachable is not connected, so a trigger dials.** An on-demand peer idle-closes its mesh links (`MeshConnection`'s idle timer) while its endpoint stays up, so it is dialable the whole time the peer table shows it absent. `broadcast_member_sync` therefore delivers over live connections *and* spawns a dial for the roster members it missed: without that, a phone would learn about a kick or a firewall suggestion only at its next group poll, and that poll is exactly what a battery-powered node lengthens (`GROUP_POLL_INTERVAL_BATTERY`, 15min on Android vs 60s elsewhere). The dial skips peers whose last attempt failed inside `ABSENT_DIAL_COOLDOWN`, because a genuinely offline device costs a timeout per roster edit and teaches us nothing. The poll survives as the backstop for the case no trigger can cover (every coordinator offline while the blob changed), and `NetworkRegistry::poll_nudge` fires it early when the data plane comes up. **The long poll is keyed on the platform, not on `on_demand`:** that is a desktop config key a wired node may set for its own reasons, and a 15-minute-stale roster is not what it asked for.
- **A tab never starts the daemon and never blocks the shell.** Completion is dynamic (the installed script is a stub that calls the binary), so it runs on a keystroke: it answers from an open IPC read within a 300ms budget, and every failure — no socket, no daemon, no reply in time — is the same answer, no candidates. `ray up` installs the stubs system-wide because that is where shells find them without an rc edit.

## Conventions

- **Writing:** plain and direct.
- **Rust:** import type names (`use std::net::Ipv6Addr;` then `Ipv6Addr`), don't inline fully-qualified paths. **Never** share an I/O resource (TUN, socket, stream) behind a `Mutex`: split read/write halves. Avoid `Mutex` generally: prefer channels, atomics, or `RwLock`/`ArcSwap` for fast non-async state.
- **Wire protocols are ALPN-versioned** (`rayfish/{mesh,files,pair,connect}/<v>`). ALPN negotiation is the *only* compatibility gate (no in-band version handshake), so when you change a wire protocol incompatibly, bump its version in the same change. Wire format = 4-byte BE length + msgpack; TUN MTU 1280.
- **Config** lives under `config::config_dir()` (`/etc/rayfish` on Linux, `~/Library/Application Support/rayfish` on macOS, i.e. the *daemon's* home, `/var/root` under launchd; `RAYFISH_CONFIG_DIR` overrides it on every platform, and daemon + CLI must both see the same value): sharded + atomic: globals in `settings.toml`, one network per `networks/<name>.toml`. Secret-bearing files are `0600 root:root`; writes go through `config::write_file` (temp file + rename). Single-value settings are not bespoke IPC: every one is a typed key, one enum per store (`GlobalKey` / `FirewallKey` / `NetworkKey` in `ray-proto/src/settings.rs`, named on the wire, `NodeKey` = global + firewall), meaning it writes over `ConfigSet`/`ConfigGet` or `NetConfigSet`/`NetConfigGet` and its behavior lives in `config::settings` (`src/config/settings.rs`). The per-store split is load-bearing: every `apply_*`/`render_*` matches its key enum exhaustively, so a new key cannot compile until each handler serving it grows an arm. Adding a setting means adding an enum variant, its `apply`/`render` arms, and a CLI arm, never a new message type.
- **IPC is one request, one response, with one exception.** `ray logs` answers
  with a run of `LogChunk` frames, ended by an `Ok` sentinel or (under
  `--follow`) not ended at all, because a day of `rayfish=debug` output is many
  times the 1 MiB frame cap and a follow has no last frame by definition. It is
  the only handler that writes to the stream instead of returning an
  `IpcMessage`, which is why it is dispatched in `handle_ipc_client` ahead of
  `handle_request`. Keep it that way: a second streaming reply is a reason to
  factor the pattern out, not to widen every handler's signature.
- **CLI help is grouped in `src/cli/help.rs`, per page.** clap has no subcommand grouping (`help_heading`/`hide_short_help` are argument-only), so a grouped `-h` list is rendered there from the clap model and the help template drops `{subcommands}`. `PAGES` maps a command path to its groups (`&[]` = the root, `&["firewall"]` = `ray firewall`); a new command must join the groups of the page it sits on or it appears nowhere, and the tests enforce both directions per page. Group a page only when it outgrows a flat list: below about eight actions a heading per two entries is noise. **`about` is one line inside 80 columns at every depth** (`every_about_fits_the_listing` walks the whole model), with the rest after a blank line, where it becomes `ray help <command> <action>`; `wrap_help` is on so those paragraphs wrap to the terminal. Subcommands stay *visible* in the clap model unless hiding them is the point: `hide = true` suppresses clap's list but `clap_complete` also skips hidden subcommands, which silently guts tab completion for a command meant to be typed — and is exactly right for one that isn't (`open`), or for an old spelling kept alive only so existing scripts keep working (`accept`, `deny`, `connections`, `auto-update`).
- **`--json` is per-command, never on the root.** It is declared on each command that renders JSON, `global = true` so it also parses after that command's action (`ray firewall show --json`). Declaring it on `Cli` would put it back on all 44 commands, most of which would ignore it in silence.
- **Logging** is `tracing`: console at `info`, rolling daily files at `rayfish=debug` (bundled by `ray report`). The daemon panic hook restores DNS then `abort()`s so the service manager restarts it (fail-fast, never limp).
- **Git:** conventional commit subjects (`feat`/`fix`/`docs`/…) so git-cliff can generate the changelog.
- **CHANGELOG:** add a user-facing `[Unreleased]` entry (`Added`/`Changed`/`Fixed`/`Performance`), describing behavior from the user's view, for any user-visible change; skip pure-internal churn (refactors, CI, chores).
- **Docs:** keep this file and README current when a feature or invariant changes: at the principle level, pointing to code rather than restating it.
