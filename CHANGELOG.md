# Changelog

All notable changes to Rayfish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

First public release.

### Added

- **P2P mesh VPN** over [iroh](https://iroh.computer) — peers connect by
  cryptographic identity (EndpointId), not IP. NAT traversal, hole-punching, and
  end-to-end encryption are handled by iroh, with encrypted relay fallback.
- **Dual-stack addressing** derived from identity: stable IPv4 in `100.64.0.0/10`
  (FNV-1a) and stable IPv6 in `200::/7` (blake3, 120-bit, never rotates).
- **Networks & access modes** — closed by default; `--open` for public networks.
  Closed networks admit via one-time **invite codes** (`ray invite`) or **live
  approval** (`ray requests` / `ray accept` / `ray deny`). The room id is a
  discovery key, never an admission credential.
- **Coordinator / membership model** — single signed `GroupBlob` per network
  published to a per-network pkarr record; gatekeeper admission, member roster,
  and `MemberApproved` broadcast so the coordinator need not be online for a
  member's later reconnects.
- **Co-coordinators** — `ray admin add` grants the network key over the
  authenticated mesh, enabling multiple machines to publish the signed blob.
- **Magic DNS** — reach peers at `name.network.ray` (A/AAAA/PTR/SOA), rebuilt
  from the roster on every membership change.
- **Per-device firewall** — directional, protocol-, port-, and network-scoped
  rules with a stateful conntrack; `firewall.toml`.
- **Trusted networks** — coordinators can suggest firewall rules that ride the
  signed blob; nodes auto-take (`--allow-trusted`) or queue them for manual
  `ray firewall accept` / `deny`.
- **Declarative provisioning** — `ray apply <spec>` reconciles trusted networks +
  suggested firewalls from a YAML/TOML/JSON spec, with `--prune`, `--dry-run`,
  `--invite-missing`, and `--example`.
- **Multi-device identity** — `ray pair` (ticket-based), plus encrypted
  backup/restore, including optional 1Password storage of the encrypted blob via
  the `op` CLI (`ray pair backup --1password` / `ray pair restore --1password`).
- **File sharing** — `ray send` / `ray files accept` over iroh-blobs.
- **mDNS local discovery** (`ray mdns on|off`, default on).
- **Service management** — `ray up`/`down`, `ray install`/`restart`/`uninstall`,
  and the Tailscale-style operator model (`ray set-operator`).
- **Audit log** — append-only peer connect/disconnect events at
  `~/.config/rayfish/audit.log`.
- **Diagnostics** — Prometheus metrics on `:9090`, rolling daily logs, and
  `ray report` to bundle logs + metrics + sanitized status.
- **Optional transports / export** — `--features tor` (Tor transport) and
  `--features otel` (OTLP span export).

[Unreleased]: https://github.com/rayfish/rayfish/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rayfish/rayfish/releases/tag/v0.1.0
