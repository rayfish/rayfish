# Rayfish

P2P mesh VPN over [iroh](https://iroh.computer). Peers are addressed by cryptographic identity, not IP; the overlay is IPv6-only (`200::/7`, derived from the identity).

## Code map

- `src/`: the `rayfish` core library and original Rust `ray` CLI.
- `ray-proto/`: shared protocol types, settings, and IPC encoding.
- `ray-mobile/`: Android UniFFI bridge; Kotlin app in `android/`.
- `ray-apple/`: Apple UniFFI bridge; Swift app and packet tunnel extension in `macos/`.

Design reasoning lives in module docs, next to the code it constrains. Read those, not a copy here.

## Build & test

```bash
cargo -q build          # --features tor, otel
cargo -q check --workspace --all-targets
cargo -q clippy --workspace --all-targets -- -D warnings
cargo -q test --workspace
cargo bench             # per-packet data path (benches/forward.rs)
just cross              # x86_64 Linux;  just deploy <ip> = build + install + start
just apk                # ray-mobile + Kotlin bindings + debug APK (cargo-ndk, JDK 17)
just android-check      # compile the Android target in a container, no NDK
tests/e2e.sh <scenario> # shell, not cargo; see tests/e2e/README.md
just macos-dev         # signed local Debug app; requires macOS and Xcode
just macos-test        # legacy daemon detection and migration
just macos-ipc-test    # provider message concurrency, send failures, and timeouts
just macos-ui-test     # live menu updates and hide-on-close behavior, no VPN
```

- For Rust changes, run `cargo fmt --all -- --check`, workspace Clippy with `--all-targets`, and tests for the affected crates before committing. Test the whole workspace when shared types or core behavior change.
- Always use `--workspace --all-targets` for `cargo check` and Clippy. A root-only check misses platform bridges and their tests.
- Use `cargo -q`. Keep build, clippy and test green at every step.
- Linux builds do not check macOS or Android conditional code. Run the relevant platform build when changing it. See `macos/README.md` for production signing and release setup.

## Never

- **Never hand-edit `android/app/src/main/java/uniffi/ray_mobile/ray_mobile.kt`.** `just apk` generates it; CI fails on a diff. A UniFFI change means regenerating and fixing the Kotlin callers in the same commit.
- **Never hand-edit `macos/Generated/`.** Regenerate the Swift bindings with `ray-apple`'s `uniffi-bindgen` and update Swift callers together; `.github/workflows/ci.yml` has the generation command.
- **Never share an I/O resource (TUN, socket, stream) behind a `Mutex`.** Split read/write halves.
- **Never add a bespoke IPC message for a single setting.** Add a variant to `GlobalKey`/`FirewallKey`/`NetworkKey` (`ray-proto/src/settings.rs`) plus its `apply`/`render` arms in `src/config/settings.rs` and a CLI arm. The enums are matched exhaustively, so a missing arm will not compile.
- **Never declare `--json` on the root command.** It goes on each command that renders JSON, with `global = true`.
- **Never let a non-daemon reader call `config::config_dir()`.** Use `config_dir_for_read` / `load_for_read`, which create nothing. An unprivileged `ray` that resolves a home-directory path invents an empty config and then reports it as the daemon's.
- **Never change a wire struct without reading `.claude/rules/wire-protocol.md`.** Field order is the wire format there. Incompatible changes need the corresponding ALPN bump in the same commit.

## Conventions

- A bare `Mutex` means the std one; the `AsyncMutex` alias for tokio's is in `src/lib.rs`. Prefer channels, atomics, or `RwLock`/`ArcSwap` over either.
- Service management goes through `init_system::InitSystem` (systemd / OpenRC / SysV), never `systemctl` directly. macOS launchd is a `#[cfg]` branch at the call site.
- The daemon runs as root and does the privileged work; clients are unprivileged. Authority is a per-request `SO_PEERCRED` UID check (`Daemon::check_authorized`), not the `0666` socket's permissions. Reads are open to any local user; mutations need root or `operator_uid`.
- IPC is one request, one response. `ray logs` is the sole streaming exception.
- An iroh handler that owns a connection and sends a final response must finish the send stream, then keep the connection alive with a bounded wait on `connection.closed()`. Do not return immediately after sending: dropping the connection can reset the stream before the peer reads the response.
- Logging is `tracing`: console at `info`, daily files at `rayfish=debug`. The panic hook restores DNS then `abort()`s so the service manager restarts it.
- CLI help groups live in `src/cli/help.rs` (`PAGES`); a new command must join its page's groups or it appears nowhere. `about` is one line under 80 columns. `hide = true` also drops a command from tab completion.
- For the command surface read `ray --help`, not a list here.

## macOS

- The network extension hosts the same Rust core as the daemon. The GUI uses NetworkExtension provider messages; the bundled Rust CLI uses the standard Unix socket. Do not recreate the CLI in Swift.
- NetworkExtension owns the interface, routes, DNS, and VPN lifetime. Use `attach_external_tun`; desktop daemon activation must not reconfigure its interface. Connect and disconnect through the app.
- Closing a window keeps the tray app alive. Cmd+Q disconnects the VPN before exiting.
- Keep Swift logging in `OSLog` under `com.rayfish.app`; keep Rust logging in `tracing`. Do not log keys, invite codes, or other credentials.
- `macos/project.yml` is the XcodeGen source. Update it when changing targets, sources, or shared build settings, and keep the checked-in project usable. Regeneration can overwrite local signing settings.
- Production releases require Developer ID signing and successful notarization for the app and DMG. Never publish an unsigned fallback. Keep certificates, private keys, profiles, and credentials out of Git.
- Preserve bundled fonts' copyright and license notices when distributing the app.

## Git

- Conventional commit subjects (`feat`/`fix`/`docs`/...) so git-cliff can generate the changelog.
- Any user-visible change gets an `[Unreleased]` CHANGELOG entry (`Added`/`Changed`/`Fixed`/`Security`/`Performance`, in that order), written from the user's view. Skip internal churn.
- Keep `docs/` untracked. It holds local plans and specifications.
