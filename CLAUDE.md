# Rayfish

P2P mesh VPN over [iroh](https://iroh.computer). Peers are addressed by cryptographic identity, not IP; the overlay is IPv6-only (`200::/7`, derived from the identity). Three crates: `rayfish` (lib + the `ray` binary), `ray-proto`, `ray-mobile` (UniFFI cdylib for `android/`).

Design reasoning lives in module docs, next to the code it constrains. Read those, not a copy here.

## Build & test

```bash
cargo -q build          # --features tor, otel
cargo -q check --workspace --all-targets
cargo bench             # per-packet data path (benches/forward.rs)
just cross              # x86_64 Linux;  just deploy <ip> = build + install + start
just apk                # ray-mobile + Kotlin bindings + debug APK (cargo-ndk, JDK 17)
just android-check      # compile the Android target in a container, no NDK
tests/e2e.sh <scenario> # shell, not cargo; see tests/e2e/README.md
```

- Always pass `--workspace --all-targets`. A bare `cargo check` builds only the root crate, so a shared-type change passes here and fails CI on the other two.
- Before committing: `cargo fmt`, then `cargo clippy --all-targets -- -D warnings`, then `cargo test`, scoped with `-p` to the crates you touched. All three crates are clean workspace-wide, so drop `-p` when a change is broad.
- Use `cargo -q`. Keep build, clippy and test green at every step.

## Never

- **Never hand-edit `android/app/src/main/java/uniffi/ray_mobile/ray_mobile.kt`.** `just apk` generates it; CI fails on a diff. A UniFFI change means regenerating and fixing the Kotlin callers in the same commit.
- **Never share an I/O resource (TUN, socket, stream) behind a `Mutex`.** Split read/write halves.
- **Never add a bespoke IPC message for a single setting.** Add a variant to `GlobalKey`/`FirewallKey`/`NetworkKey` (`ray-proto/src/settings.rs`) plus its `apply`/`render` arms in `src/config/settings.rs` and a CLI arm. The enums are matched exhaustively, so a missing arm will not compile.
- **Never declare `--json` on the root command.** It goes on each command that renders JSON, with `global = true`.
- **Never let a non-daemon reader call `config::config_dir()`.** Use `config_dir_for_read` / `load_for_read`, which create nothing. An unprivileged `ray` that resolves a home-directory path invents an empty config and then reports it as the daemon's.
- **Never widen a wire struct without reading `.claude/rules/wire-protocol.md`.** Field order is the wire format there.

## Conventions

- A bare `Mutex` means the std one; the `AsyncMutex` alias for tokio's is in `src/lib.rs`. Prefer channels, atomics, or `RwLock`/`ArcSwap` over either.
- Service management goes through `init_system::InitSystem` (systemd / OpenRC / SysV), never `systemctl` directly. macOS launchd is a `#[cfg]` branch at the call site.
- The daemon runs as root and does the privileged work; clients are unprivileged. Authority is a per-request `SO_PEERCRED` UID check (`Daemon::check_authorized`), not the `0666` socket's permissions. Reads are open to any local user; mutations need root or `operator_uid`.
- IPC is one request, one response. `ray logs` is the sole streaming exception.
- Logging is `tracing`: console at `info`, daily files at `rayfish=debug`. The panic hook restores DNS then `abort()`s so the service manager restarts it.
- CLI help groups live in `src/cli/help.rs` (`PAGES`); a new command must join its page's groups or it appears nowhere. `about` is one line under 80 columns. `hide = true` also drops a command from tab completion.
- For the command surface read `ray --help`, not a list here.

## Git

- Conventional commit subjects (`feat`/`fix`/`docs`/...) so git-cliff can generate the changelog.
- Any user-visible change gets an `[Unreleased]` CHANGELOG entry (`Added`/`Changed`/`Fixed`/`Security`/`Performance`, in that order), written from the user's view. Skip internal churn.
