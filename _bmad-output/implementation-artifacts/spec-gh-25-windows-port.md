---
title: 'Windows desktop port for rayfish issue #25'
type: 'feature'
created: '2026-08-02'
status: 'done'
baseline_commit: 'e07d79593c52271c8110f4f271576daa3d34d8d7'
review_loop_iteration: 1
context:
  - '{project-root}/Cargo.toml'
  - '{project-root}/ray-proto/src/ipc.rs'
  - '{project-root}/src/tun.rs'
  - '{project-root}/src/dns/config.rs'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Rayfish issue #25 is blocked on Windows because the daemon assumes Unix TUN access, Unix-domain IPC with descriptor passing, Unix privilege APIs, and Unix-only SSH/PTY dependencies. A Windows build therefore fails before project code is compiled.

**Approach:** Add a narrow Windows platform implementation while preserving the existing packet path, message schema, Unix transport, and Linux/macOS behavior. The first supported artifact is x86_64-pc-windows-msvc with a signed Wintun DLL, Windows service lifecycle, named-pipe authorization, interface DNS/routing, and unprivileged CLI operation.

## Boundaries & Constraints

**Always:** Keep `TunRead`/`TunWrite` and the msgpack IPC wire contract stable; use target-specific `cfg` gates; run the daemon as LocalSystem and authorize clients by Windows SID; store service state under `%ProgramData%\rayfish`; use signed Wintun binaries with a pinned checksum; keep all privileged operations in the daemon.

**Ask First:** Expanding scope to Windows ARM64, Windows SSH/PTY support, a breaking IPC schema, or a different service identity/ACL model.

**Never:** Do not remove Unix support, weaken pipe ACL/SID checks, pass filesystem paths as a Windows file-transfer fallback, or make the unprivileged client require Administrator elevation.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Service install | Elevated Administrator, fresh host | Service and `%ProgramData%\rayfish` are created; pipe ACL grants Administrators and configured operator SID | Fail closed with actionable elevation/install error |
| IPC request | Authorized or unauthorized user token | Authorized SID reaches daemon; unauthorized SID is rejected before dispatch | Return permission error; record security event without leaking details |
| VPN activation | Service running, Wintun available | TUN opens, link/routes/DNS apply, packet forwarding starts | Roll back link/routes/DNS and report the failing Windows API |
| VPN deactivation | Active session or partial activation | DNS/routes/link are reverted and service remains usable | Best-effort cleanup; retain original error and log incomplete cleanup |
| File send | Binary file, including payload >1 MiB | In-band chunks arrive in order and produce the same remote file | Reject malformed sequence/overflow; remove partial transfer |
| Missing Wintun | DLL absent or checksum mismatch | Startup refuses unsafe driver load | Explain required signed artifact and checksum |

</frozen-after-approval>

## Code Map

- `Cargo.toml` / `ray-proto/Cargo.toml` -- target-gate Unix dependencies and add Windows dependencies/features.
- `ray-proto/src/ipc.rs` -- generic framed transport; keep Unix SCM_RIGHTS behind `cfg(unix)` and add Windows peer identity hooks.
- `src/tun.rs` / `src/daemon/mesh/runtime.rs` -- introduce `PlatformTun`/desktop pass-through and Wintun-backed open/link/route operations.
- `src/dns/config.rs` -- Windows `DnsConfigurator` using interface DNS APIs and reversible state.
- `src/daemon/mesh/bootstrap.rs` / `src/daemon/mod.rs` -- named-pipe listener, SID authorization, and platform-neutral request dispatch.
- `src/cli/service.rs` / `src/main.rs` -- Windows service install/start/stop/grant and non-root client behavior.
- `src/config.rs` / `src/logdir.rs` -- `%ProgramData%\rayfish` paths and Windows-safe permissions.
- `src/cli/files.rs` / `src/daemon/file_service.rs` -- Windows in-band chunk upload; preserve Unix fd path.
- `src/ssh.rs` -- compile-safe Windows unsupported response for Unix PTY operations.
- `.github/workflows/windows.yml` / installer metadata -- MSVC build, Wintun packaging, MSI lifecycle checks.

## Tasks & Acceptance

**Execution:**
- [x] `Cargo.toml` and `ray-proto/Cargo.toml` -- gate `uzers`, `pty-process`, Unix fd/socket imports; add `windows-service`, `windows-sys`, and Wintun integration -- make the MSVC target compile.
- [x] `ray-proto/src/ipc.rs` -- parameterize framed I/O over async read/write transports and isolate descriptor passing -- preserve existing Unix frames while enabling named pipes.
- [x] `src/tun.rs`, `src/daemon/mesh/runtime.rs` -- add `PlatformTun` with desktop delegation and Windows implementation -- reuse the current packet/forwarding path.
- [x] `src/dns/config.rs`, `src/config.rs`, `src/logdir.rs` -- implement reversible Windows DNS and service paths -- avoid Unix filesystem assumptions.
- [x] `src/daemon/mesh/bootstrap.rs`, `src/daemon/mod.rs`, `src/cli/service.rs`, `src/main.rs` -- implement Windows service, named-pipe ACL/SID checks, and client commands -- preserve least privilege.
- [x] `src/cli/files.rs`, `src/daemon/file_service.rs` -- add bounded in-band chunks and cleanup -- support Windows transfer without SCM_RIGHTS.
- [x] `src/ssh.rs`, `.github/workflows/windows.yml`, installer metadata -- provide Windows-safe SSH stub, CI, signed Wintun/MSI packaging -- make unsupported scope explicit.

**Acceptance Criteria:**
- Given MSVC/Windows SDK and the x86_64 target, when `cargo check --target x86_64-pc-windows-msvc --features desktop --bin ray` runs, then it succeeds without Unix-only dependency errors.
- Given Linux/macOS, when existing tests and checks run, then packet forwarding, IPC, service behavior, and DNS behavior remain unchanged.
- Given an elevated Windows 11 install, when the service is installed/started/stopped/uninstalled, then all lifecycle operations are idempotent and leave no stale pipe, route, DNS, or temporary state.
- Given an authorized unprivileged client, when it sends a control request, then the LocalSystem daemon accepts it; an unauthorized SID is rejected.
- Given a working Wintun DLL, when VPN activation runs, then the adapter, routes, DNS, packet forwarding, and reversible deactivation all succeed.
- Given a binary file larger than 1 MiB, when `ray send` runs, then the receiver reconstructs identical bytes and interrupted transfers clean up.

## Spec Change Log

## Design Notes

The public platform seam follows the existing Android/iOS refactor direction: `PlatformTun` owns acquisition and privileged link/route operations, while the daemon keeps packet processing platform-neutral. IPC framing remains length-delimited msgpack; only transport construction and Unix descriptor passing become target-specific. Windows SSH/PTY is deliberately a compile-safe v1 limitation because the current implementation depends on Unix account and PTY APIs.

## Verification

### ZOMBIE-D / DDD test protocol

| Dimension | Windows cases | Evidence |
|-----------|---------------|----------|
| Zero/overflow | empty file, exact 256 KiB chunk, >1 MiB payload, >4 GiB declaration, chunk overflow | bounded chunk loop + protocol roundtrip test |
| Order/identity | chunk-before-begin, duplicate/non-final `done`, disconnect mid-upload, unknown SID | daemon rejects unexpected frames, SID check precedes dispatch, temp cleanup guard |
| Boundary/dependency | missing Wintun, checksum/signature failure, missing adapter/PowerShell, absent service | fail-closed errors; Wintun verification script; SCM/CI gates |
| Injection/isolation | filename path components, SDDL operator/Admin/System ACL, arbitrary client path | basename sanitization; server-created temp path; pipe ACL + SID authorization |
| Determinism/DDD | host regression, Windows target compile, clippy, protocol serialization | `cargo test --workspace`, Windows `cargo check`, `cargo clippy -D warnings` |

**Commands:**
- `cargo check --target x86_64-pc-windows-msvc --features desktop --bin ray` -- expected: success.
- `cargo test --workspace` -- expected: success on host.
- `cargo clippy --workspace --all-targets -- -D warnings` -- expected: success.
- `cargo wix --version` and MSI build command -- expected: installer artifact generated.

**Manual checks (if no CLI):**
- Windows 11 elevated smoke test covers Wintun adapter, routes, DNS apply/revert, pipe ACL/SID authorization, service recovery, reboot persistence, and MSI uninstall cleanup.

## Review Outcome

- Three-agent BMAD Quick Dev review completed: root integrator + Blind Hunter + Edge Case Hunter.
- Patched: fail-closed pipe ACL/SID validation, SCM stop/start waits, MSI operator lockout, exact adapter selection, Windows CGNAT preflight, staged-transfer authorization/timeouts/cleanup, transfer error propagation, route rollback/removal, and DNS restoration.
- Deferred with rationale: Windows MSI-aware self-update, global pipe concurrency quota, IPv6/transactional NRPT state, Windows download-user auto-accept, and standalone verifier UX; see [`deferred-work.md`](deferred-work.md).

## Suggested Review Order

**Transport and authorization**

- Start with the stable framed IPC seam and Windows named-pipe transport.
  [`ipc.rs:924`](../../ray-proto/src/ipc.rs#L924)

- Verify SID extraction, fail-closed ACL application, bounded upload staging, and cleanup.
  [`bootstrap.rs:808`](../../src/daemon/mesh/bootstrap.rs#L808)

- Confirm read-only versus mutating request policy at the daemon boundary.
  [`mod.rs:780`](../../src/daemon/mod.rs#L780)

**Windows privileged lifecycle**

- Review LocalSystem SCM install and idempotent stop/start synchronization.
  [`windows_service.rs:44`](../../src/windows_service.rs#L44)

- Check service paths and persisted operator SID under ProgramData.
  [`config.rs:707`](../../src/config.rs#L707)

**Dataplane and DNS**

- Follow the PlatformTun façade into Windows route, link, and rollback operations.
  [`tun.rs:187`](../../src/tun.rs#L187)

- Verify exact adapter binding and reversible DNS/NRPT configuration.
  [`config.rs:240`](../../src/dns/config.rs#L240)

- Inspect standby cleanup ordering before the interface is disabled.
  [`runtime.rs:1264`](../../src/daemon/mesh/runtime.rs#L1264)

**Packaging and transfer**

- Review bounded in-band Windows file upload and server-side filename handling.
  [`files.rs:78`](../../src/cli/files.rs#L78)

- Validate signed Wintun staging and MSI service lifecycle metadata.
  [`windows.yml:27`](../../.github/workflows/windows.yml#L27)

- Check the installer components and deliberate first-run operator enrollment.
  [`main.wxs:27`](../../wix/main.wxs#L27)

**Regression evidence**

- Run host tests, Windows target check, clippy, and the manual Windows 11 smoke matrix.
  [`spec-gh-25-windows-port.md:94`](spec-gh-25-windows-port.md#L94)
