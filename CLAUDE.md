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
```

Use `cargo -q` for all cargo commands. Keep `build` / `clippy` / `test` green at every step.

## Run

The daemon (`ray daemon`) owns the TUN device + iroh endpoint and runs as a system service; the CLI talks to it over Unix-socket IPC. Full command surface + flags: `ray --help`, `ray <cmd> --help`.

Service management never calls `systemctl` directly: `init_system::InitSystem` detects systemd / OpenRC / SysV init and owns the per-init unit template (`contrib/rayfish.{service,openrc,init}`), install path, and start/stop/enable commands. macOS (launchd) is a `#[cfg]` branch at the call sites.

```bash
sudo ray up | down            # activate / standby (down keeps peer connections, drops only the data plane)
sudo ray start | stop | restart | install | uninstall | set-operator
ray create | join | leave | nuke | kick | ephemeral | hostname | status
ray invite | requests | accept | deny | admin        # admission + coordinators
ray connect | connections | contact | pair | unpair  # direct links + multi-device identity
ray firewall … | apply | alias | identityof          # policy
ray exit-node allow | disallow | use | none | status  # internet gateway (offer: Linux/macOS/BSD, use: Linux/macOS)
ray send | files | config | gui | mdns | auto-update | update | ping | netcheck | report
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
| DNS | `src/dns.rs` (`.ray` responder), `src/dns_config.rs` (OS DNS integration) |
| Config / identity | `src/config.rs`, `src/identity.rs` |
| Misc | `src/stats.rs`, `src/ratelimit.rs`, `src/audit.rs`, `src/logdir.rs`, `src/onepassword.rs` |
| Mobile core | `ray-mobile/src/lib.rs` (UniFFI `Node`), `android_tun.rs` (VpnService fd) |
| Android app | `android/app/src/main/java/xyz/rayfish/android/` (`ui/screens/*`, `RayfishVpnService.kt`, `NodeHolder.kt`) |

## Mobile

Android runs the same core, not a reimplementation. `ray-mobile` is a UniFFI cdylib exposing a `Node` that wraps a headless `DaemonState` (`build_headless`), so create/join/pair/status/firewall all go through the desktop code path. There is no daemon process and no IPC socket on Android: Kotlin calls the `Node` directly.

- **Platform specifics stay in `ray-mobile`.** The TUN fd comes from Android's `VpnService` and is handled in `android_tun.rs`; `RustlsInit.nativeInit(context)` must run once after `System.loadLibrary` to hand the `JavaVM` + app `Context` to `ndk-context` (system DNS) and `rustls-platform-verifier` (trust store). Everything else is a thin map from the core's `IpcMessage` results to UniFFI records.
- **Same control/data plane split.** `Node::start` brings up the control plane; `Node::up` / `Node::down` attach and detach the forward loop over the VpnService fd, leaving peer connections up.
- **Bindings are generated, not written.** `android/app/src/main/java/uniffi/ray_mobile/ray_mobile.kt` is regenerated by `just apk`; never hand-edit it. Changing the UniFFI surface means regenerating and fixing the Kotlin callers in the same change.
- **UI is Compose**, one screen per tab (`HomeScreen`, `NetworksScreen`, `NetworkDetailScreen`, `YouScreen`) with shared widgets in `ui/components/Components.kt` and QR scan/render in `ui/qr/`.

## Design invariants

The rules the code upholds. Read the code for the mechanics.

- **Reachability = a shared network.** Two peers exchange packets iff they share ≥1 network (a QUIC connection only exists within one; the receiver also drops any datagram whose handle-tagged network its verified roster no longer shares with the sender). The network split is coarse access; the per-device firewall is the fine layer.
- **Room id ≠ admission.** The network public key is a discovery key, never a credential. Open networks auto-admit; closed networks gate on a one-time invite, a reusable key (carried in the signed blob), or live approval (`ray accept`).
- **The signed `GroupBlob` is the source of truth.** One pkarr record per network, signed by the per-network key (the pkarr address *is* the public key, so records are MITM-resistant). Roster, suggested firewall, reusable keys, and `nullifiers` (`ray unpair`) all ride it. Members reconverge from the signed record on the 60s poll or a payload-free `MemberSync`/`BlobUpdated` **trigger**: control messages are triggers, never trusted data.
- **Coordinator = network-key holder.** Any holder can admit, suggest firewall, kick, and republish; `ray admin add` grants the key (co-coordinator). Admission survives any single coordinator being offline (the joiner dials the full coordinator set).
- **Firewall is secure-by-default.** Inbound TCP/UDP denied, inbound ICMP allowed (a seeded, removable rule), outbound allowed; a stateful conntrack lets return traffic back. Coordinator suggestions are advisory and consented per-node; local rules are never touched by reconverge.
- **Hostname authority = invite binding.** An invite-bound hostname is assigned exactly and a colliding claim is rejected; a free hostname gets suffix collision resolution. The roster is the single source of truth for `*.ray` DNS.
- **Data plane vs control plane.** The daemon connects every saved network at startup and keeps those connections for its lifetime (dropped only on leave/nuke/shutdown). `up`/`down` (`activate`/`deactivate`) toggle only the data plane (TUN link, routes, Magic DNS, forward gate); `start`/`stop` toggle the whole process.
- **A tab never starts the daemon and never blocks the shell.** Completion is dynamic (the installed script is a stub that calls the binary), so it runs on a keystroke: it answers from an open IPC read within a 300ms budget, and every failure — no socket, no daemon, no reply in time — is the same answer, no candidates. `ray up` installs the stubs system-wide because that is where shells find them without an rc edit.

## Conventions

- **Writing:** plain and direct.
- **Rust:** import type names (`use std::net::Ipv6Addr;` then `Ipv6Addr`), don't inline fully-qualified paths. **Never** share an I/O resource (TUN, socket, stream) behind a `Mutex`: split read/write halves. Avoid `Mutex` generally: prefer channels, atomics, or `RwLock`/`ArcSwap` for fast non-async state.
- **Wire protocols are ALPN-versioned** (`rayfish/{mesh,files,pair,connect}/<v>`). ALPN negotiation is the *only* compatibility gate (no in-band version handshake), so when you change a wire protocol incompatibly, bump its version in the same change. Wire format = 4-byte BE length + msgpack; TUN MTU 1280.
- **Config** lives under `config::config_dir()` (`/etc/rayfish` on Linux, `~/.config/rayfish` on macOS; `RAYFISH_CONFIG_DIR` overrides it on every platform, and daemon + CLI must both see the same value): sharded + atomic: globals in `settings.toml`, one network per `networks/<name>.toml`. Secret-bearing files are `0600 root:root`; writes go through `config::write_file` (temp file + rename). Single-value settings are not bespoke IPC: every one is a typed key, one enum per store (`GlobalKey` / `FirewallKey` / `NetworkKey` in `ray-proto/src/settings.rs`, named on the wire, `NodeKey` = global + firewall), meaning it writes over `ConfigSet`/`ConfigGet` or `NetConfigSet`/`NetConfigGet` and its behavior lives in `config::settings` (`src/config/settings.rs`). The per-store split is load-bearing: every `apply_*`/`render_*` matches its key enum exhaustively, so a new key cannot compile until each handler serving it grows an arm. Adding a setting means adding an enum variant, its `apply`/`render` arms, and a CLI arm, never a new message type.
- **CLI help is grouped in `src/cli/help.rs`.** clap has no subcommand grouping (`help_heading`/`hide_short_help` are argument-only), so the `-h` command list is rendered there from the clap model and the help template drops `{subcommands}`. A new command must join a `GROUPS` entry or it appears nowhere (tests enforce both directions). Subcommands stay *visible* in the clap model on purpose: `hide = true` would suppress clap's list but `clap_complete` skips hidden subcommands, silently gutting tab completion. Keep each `about` to one line inside 80 columns and put the rest after a blank line, where it becomes `ray help <command>`.
- **`--json` is per-command, never on the root.** It is declared on each command that renders JSON, `global = true` so it also parses after that command's action (`ray firewall show --json`). Declaring it on `Cli` would put it back on all 44 commands, most of which would ignore it in silence.
- **Logging** is `tracing`: console at `info`, rolling daily files at `rayfish=debug` (bundled by `ray report`). The daemon panic hook restores DNS then `abort()`s so the service manager restarts it (fail-fast, never limp).
- **Git:** conventional commit subjects (`feat`/`fix`/`docs`/…) so git-cliff can generate the changelog.
- **CHANGELOG:** add a user-facing `[Unreleased]` entry (`Added`/`Changed`/`Fixed`/`Performance`), describing behavior from the user's view, for any user-visible change; skip pure-internal churn (refactors, CI, chores).
- **Docs:** keep this file and README current when a feature or invariant changes: at the principle level, pointing to code rather than restating it.
