# Contributing to Rayfish

Thanks for your interest in improving Rayfish! This guide covers the development
workflow.

## Prerequisites

- Rust **1.85+** (the project uses the 2024 edition).
- Linux or macOS. The daemon owns a TUN device and configures system DNS, so
  running it end-to-end requires root (see below); building and testing do not.

## Build, test, lint

Use `cargo -q` for a quieter output.

```bash
cargo -q build                 # debug build of the `ray` binary
cargo -q build --features tor   # optional Tor transport
cargo -q build --features otel  # optional OTLP span export
cargo -q check
cargo -q test                   # unit tests (no privileges needed)
cargo -q clippy --all-targets   # must be warning-clean
```

CI runs `cargo check`, `cargo clippy -D warnings`, and `cargo test` on every PR.
Please make sure all three pass locally before opening one.

## Running the daemon locally

The always-root daemon does the privileged work; the CLI is unprivileged and
talks to it over a Unix socket (`/var/run/rayfish/rayfish.sock`). Authority comes
from a per-request `SO_PEERCRED` UID check, not socket permissions.

```bash
sudo ray up            # first run installs + starts the system service, then activates
ray status             # unprivileged: read-only commands are open to any local user
ray create --hostname dev
```

`ray up`/`ray install` auto-grant operator access to `$SUDO_USER`, so subsequent
mutating commands run without sudo. `sudo ray set-operator <user>` authorizes
another user. `ray down` puts the daemon on standby without killing it.

For cross-compiling and remote deploys during development, see the `justfile`
(`just cross`, `just deploy <ip>`, `just deploy-dev <ip>`).

## Code conventions

`CLAUDE.md` documents the architecture, module layout, and key flows in depth —
read it before making non-trivial changes. A few load-bearing rules:

- Never share an I/O resource (TUN, sockets, streams) behind a `Mutex` — split
  into read/write halves. Prefer channels, atomics, or `RwLock`/`ArcSwap` over
  locks for shared state.
- Use `tracing` for logging (spans on network lifecycle handlers and per-peer
  tasks). The daemon is fail-fast: panics are logged and the process aborts so
  the service manager restarts it.
- Update the docs (`CLAUDE.md`, `README.md`, `CHANGELOG.md`) when you finish a
  feature or a significant change.

## Pull requests

- Keep changes focused and accompanied by tests where practical.
- Note user-facing changes under `## [Unreleased]` in `CHANGELOG.md`.
- Make sure the working tree is clean and `cargo clippy` / `cargo test` pass.

## Security issues

Please do **not** open public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for private disclosure.
