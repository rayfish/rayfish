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

Pull request and branch checks use GitHub-hosted runners. Maintainers can
enable alternate runners for artifact builds:

- Set `BOAT_BUILDS_ENABLED=true` after linking the repository in [Boat CI](https://docs.boat.dev/ci),
  activating a paid plan, and allowing the maintainers who trigger builds.
  Boat builds the Linux x86-64 musl CLI and the signed Android APK.
- Set `WARPBUILD_MACOS_ENABLED=true` after enabling [WarpBuild for the public repository](https://www.warpbuild.com/docs/ci/public-repos).
  WarpBuild builds both Mac CLI targets and the signed Apple Silicon app.
- GitHub builds the native Intel app, Windows artifacts, Linux ARM64 binaries,
  and Linux GNU binaries that target the Ubuntu 22.04 glibc baseline.
  Remove a provider variable to send its builds back to GitHub.

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

`AGENTS.md` maps the crates and records build commands and project conventions.
Read the relevant module docs for design details. A few rules:

- Never share an I/O resource (TUN, sockets, streams) behind a `Mutex`; split
  into read/write halves. Prefer channels, atomics, or `RwLock`/`ArcSwap` over
  locks for shared state.
- Use `tracing` for logging (spans on network lifecycle handlers and per-peer
  tasks). The daemon is fail-fast: panics are logged and the process aborts so
  the service manager restarts it.
- Update the docs (`AGENTS.md`, `README.md`) when you finish a
  feature or a significant change.

## Pull requests

- Keep changes focused and accompanied by tests where practical.
- Add a new file under `changelogs/unreleased/` for each user-facing change.
  Use the issue or branch name, such as `123-file-resume.md`. Add Markdown
  bullets under `### Added`, `### Changed`, `### Fixed`, `### Security`, or
  `### Performance`. Run `python3 scripts/changelog.py check`.
- Make sure the working tree is clean and `cargo clippy` / `cargo test` pass.

## Release notes

Preview pending notes with `python3 scripts/changelog.py pending`. Before
tagging a stable release, run `python3 scripts/changelog.py freeze VERSION`
with the new version (without the `v` prefix). Commit `CHANGELOG.md` and the
fragment deletions so the tag includes the version's notes. Nightlies and
prereleases render the pending files without consuming them.

## Security issues

Please do **not** open public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for private disclosure.
