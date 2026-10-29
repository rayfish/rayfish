# Rayfish

**Your machines, on one private network, anywhere.**

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL%202.0-brightgreen.svg)](LICENSE)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)

Rayfish is a peer-to-peer mesh VPN for your computers, phones, servers, and
friends' machines. It creates encrypted private networks without an account,
control server, or infrastructure to host.

Peers connect directly when possible and use encrypted relays when they cannot.
Each device has a stable address derived from its cryptographic identity, plus a
name such as `alice.gaming.ray` through Magic DNS.

Rayfish is experimental, pre-1.0 software and has not had an independent
security audit. Do not rely on it for critical systems yet.

## Features

- **No control server.** Peers discover each other through a DHT, so there is
  no account, policy server, or coordination service to run or trust.
- **Direct encrypted connections.** iroh handles NAT traversal and hole
  punching, with encrypted relay fallback when a direct path is unavailable.
- **Identity-based addressing.** Each device gets a stable IPv6 address from its
  cryptographic identity, without a central address allocator.
- **Magic DNS.** Reach a peer at a name such as `alice.gaming.ray` instead of
  remembering its address.
- **Private by default.** Closed networks support one-time invitations, live
  approval, reusable fleet keys, and member removal.
- **Local access control.** Each device enforces its own firewall rules and can
  provide keyless mesh SSH without replacing the host SSH server.
- **More than a tunnel.** Rayfish includes exit nodes, direct file sharing,
  multi-device identity, and declarative network provisioning.
- **Cross-platform.** Linux, macOS, Windows, Android, and FreeBSD are supported
  at different maturity levels.

## Install

### macOS

[Download the signed and notarized macOS DMG](https://github.com/rayfish/rayfish/releases/latest).
Apple Silicon and Intel builds are available. Drag Rayfish into Applications,
open it, then approve the network extension.

### Windows

[Download the x64 Windows installer](https://github.com/rayfish/rayfish/releases/latest/download/ray-windows-x86_64.msi).
ARM64 users can install from an elevated PowerShell terminal:

```powershell
irm https://rayfish.xyz/install.ps1 | iex
```

### Linux and standalone CLI

```bash
curl -fsSL https://rayfish.xyz/install.sh | sh
sudo ray up
```

The script installs the CLI and background service on Linux and macOS. See the
[installation guide](https://rayfish.xyz/docs/02-getting-started) for platform
details, updates, and building from source. All binaries and checksums are on the
[releases page](https://github.com/rayfish/rayfish/releases/latest).

### Desktop app or daemon

The macOS app does not run the standalone daemon. The Rayfish core runs inside
Apple's Network Extension, and both the app and its bundled `ray` command talk
to that extension. The standalone macOS binary instead installs a root launchd
daemon and has no native desktop app. Choose one installation: the app imports
an existing standalone setup and stops its old daemon.

On Windows there is no daemonless mode. The MSI installs a LocalSystem service
that owns the Wintun adapter and keeps the VPN running. The desktop window, tray
icon, and `ray.exe` are clients of that service. Closing the window leaves the
app in the tray and does not stop the service or disconnect the VPN.

## Quick start

Create a private network and invite another device:

```bash
ray create --name gaming
ray invite gaming

# On the other device:
ray join <invite-code>
```

Then reach peers by name:

```bash
ping alice.gaming.ray
ray status
```

Networks are closed by default. Invite codes are single-use, and peers can also
request approval from the network coordinator.

## Rootless Linux

Run without sudo, a TUN device or host route/DNS changes:

```bash
ray rootless --socks5 127.0.0.1:1080 --http 127.0.0.1:8080
# In another terminal:
ray join <network-key>
ray status
curl --proxy socks5h://127.0.0.1:1080 --proxy-user ray http://peer.network.ray/
curl --proxy http://127.0.0.1:8080 --proxy-user ray http://peer.network.ray/
```

curl prompts for the password saved in the state directory's `proxy-password`
file. Both proxies require username `ray` and that generated password. The HTTP
proxy supports HTTP requests and HTTPS through CONNECT. Mesh names resolve
inside Rayfish. Only applications using the proxy or a forward use the mesh.
TCP over mesh IPv6 is supported; UDP, exit nodes and automatic system routing
are unavailable. Existing peers need no changes.

`--forward 8080=peer.network.ray:80` opens a local TCP forward. Other local
users can access that port; use authenticated SOCKS5 for private access.
`--expose 8022=127.0.0.1:22` exposes only that local service on mesh port 8022,
subject to the mesh firewall. No other host listeners are exposed.

State and logs live under `${XDG_DATA_HOME:-$HOME/.local/share}/rayfish/rootless`.
IPC is private to the owning Unix user and root. `RAYFISH_ROOTLESS_DIR` selects
another private state directory for both daemon and CLI. Use Ctrl-C or
`ray stop` to stop; `ray down` pauses packet forwarding. Commands prefer your
running rootless instance, otherwise they use the system daemon. Use `--system`
to select the system daemon or `--rootless` to select your private instance
explicitly. System service commands such as `install` and `restart` always target
the system daemon. Startup prints the actual proxy addresses and usage commands.

## Documentation

The [official Rayfish documentation](https://rayfish.xyz/docs) covers setup,
network management, security, configuration, and the complete CLI.

- [Introduction and architecture](https://rayfish.xyz/docs/01-introduction)
- [Getting started](https://rayfish.xyz/docs/02-getting-started)
- [CLI reference](https://rayfish.xyz/docs/13-cli-reference)
- [Security model](https://rayfish.xyz/docs/26-security-model)

## Development

Rayfish is written in Rust and built on [iroh](https://iroh.computer). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and project
conventions.

```bash
cargo -q build
cargo -q test --workspace
```

## Project links

- [Changelog](CHANGELOG.md)
- [Releases](https://github.com/rayfish/rayfish/releases)
- [Issue tracker](https://github.com/rayfish/rayfish/issues)
- [Security policy](SECURITY.md)
- [MPL-2.0 license](LICENSE)
