#!/bin/sh
#
# Rayfish installer. Installs the `ray` binary from the latest GitHub release.
#
#   curl -fsSL https://rayfish.xyz/install.sh | sh
#
# Options (env vars):
#   INSTALL_DIR      target dir (default: /usr/local/bin)
#   RAY_VERSION      pin a release tag, e.g. v0.1.0 (default: latest)
#   RAY_SKIP_VERIFY  set to 1 to install without checksum verification
#
# This file is the canonical copy. rayfish.xyz serves a byte-identical copy from
# the public-www repo, and its CI fails if the two drift.
#
# POSIX sh: this is piped to `sh`, which is dash on most Linux distros and does
# not support bash-only options like `set -o pipefail`. `local` is not in POSIX
# either, but every shell that can be /bin/sh here (dash, ash/busybox, bash)
# implements it, so shellcheck is pointed at the dash dialect.
# shellcheck shell=dash
set -eu

REPO="rayfish/rayfish"
BIN="ray"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${RAY_VERSION:-latest}"
SKIP_VERIFY="${RAY_SKIP_VERIFY:-0}"

if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; BLUE=''; NC=''
fi
info()  { printf "${BLUE}%s${NC}\n" "$*"; }
ok()    { printf "${GREEN}%s${NC}\n" "$*"; }
err()   { printf "${RED}%s${NC}\n" "$*" >&2; }
die()   { err "$*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need curl
need mktemp
need install

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Lowest glibc the gnu Linux binaries are built against (CI runs on
# ubuntu-22.04 = glibc 2.35). A host below this can't run the gnu build.
GLIBC_MIN="2.35"

# Sets the globals OS and ASSET (base asset name, no libc suffix).
#
# Call this directly, never as `$(detect_asset)`: a command substitution runs in
# a subshell, so the OS it sets there would be lost in the caller and the `set
# -u` read below would abort the script.
detect_asset() {
  local arch
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="macos" ;;
    *) die "unsupported OS: $OS (Windows support is planned)" ;;
  esac
  case "$arch" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) die "unsupported architecture: $arch" ;;
  esac
  ASSET="${BIN}-${OS}-${arch}"
}

# Whether this Linux host needs the static musl binary instead of the glibc
# one: true on musl distros (Alpine) and on glibc older than the build floor.
# Conservative: if the libc can't be identified, trust the gnu build.
linux_needs_musl() {
  local have lowest
  # Alpine and friends: ldd reports musl on stderr.
  ldd --version 2>&1 | grep -qi musl && return 0
  have="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
  [ -n "$have" ] || have="$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')"
  [ -n "$have" ] || return 1
  lowest="$(printf '%s\n%s\n' "$have" "$GLIBC_MIN" | sort -V 2>/dev/null | head -1)"
  [ "$have" != "$GLIBC_MIN" ] && [ "$lowest" = "$have" ] && return 0
  return 1
}

# True if a URL resolves to an actual asset (HEAD, following redirects).
asset_exists() { curl -fsIL "$1" >/dev/null 2>&1; }

# Base URL for the chosen release (latest = the redirecting "latest" path).
release_base() {
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/${REPO}/releases/latest/download"
  else
    echo "https://github.com/${REPO}/releases/download/${VERSION}"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "no sha256sum or shasum on this host, cannot verify the download.
Install one, or set RAY_SKIP_VERIFY=1 to install unverified."
  fi
}

# The checksum sidecar is served from the same origin as the binary, so this
# catches corruption and truncation, not a compromised release. It is still the
# integrity floor: never skip it silently, since every release publishes one.
verify_sha256() {
  local file="$1" sha_file="$2" expected actual
  expected="$(head -n 1 "$sha_file" | cut -d' ' -f1)"
  case "$expected" in
    "" | *[!0-9a-fA-F]*) die "malformed checksum sidecar for $(basename "$file")" ;;
  esac
  actual="$(sha256_of "$file")"
  [ "$actual" = "$expected" ] || die "checksum mismatch
  expected: $expected
  got:      $actual"
  ok "checksum verified"
}

# The nearest existing directory at or above $1. A target that does not exist
# yet is not writable, so testing $INSTALL_DIR itself would demand sudo for a
# path the user can perfectly well create (~/.local/bin, typically) and leave a
# root-owned directory in their home.
existing_ancestor() {
  local d="$1" parent
  while [ ! -d "$d" ]; do
    parent="$(dirname "$d")"
    [ "$parent" != "$d" ] || break
    d="$parent"
  done
  echo "$d"
}

main() {
  local asset base url sudo=""
  detect_asset
  asset="$ASSET"
  base="$(release_base)"

  # On Linux, switch to the static musl asset when the glibc binary won't run
  # here (musl distro, or glibc older than the build floor) but only if a musl
  # asset was actually published for this version: older releases are gnu-only.
  if [ "$OS" = "linux" ] && linux_needs_musl; then
    if asset_exists "${base}/${asset}-musl"; then
      info "glibc is unsuitable here; using the static musl build"
      asset="${asset}-musl"
    else
      info "glibc looks unsuitable but no musl build is published for ${VERSION}; trying glibc anyway"
    fi
  fi

  url="${base}/${asset}"

  info "Downloading ${asset} (${VERSION}) ..."
  curl -fsSL "$url" -o "$TMP/$BIN" \
    || die "download failed: no release asset at $url
(does a published release exist yet for this platform?)"

  if curl -fsSL "${url}.sha256" -o "$TMP/$BIN.sha256" 2>/dev/null; then
    verify_sha256 "$TMP/$BIN" "$TMP/$BIN.sha256"
  elif [ "$SKIP_VERIFY" = "1" ]; then
    info "no .sha256 sidecar found; RAY_SKIP_VERIFY=1, installing unverified"
  else
    die "no checksum published at ${url}.sha256
Every Rayfish release ships a .sha256 sidecar, so this should not happen.
Refusing to install an unverified binary. Set RAY_SKIP_VERIFY=1 to override."
  fi

  chmod +x "$TMP/$BIN"

  # Install. Use sudo when the target dir isn't writable by the current user.
  if [ ! -w "$(existing_ancestor "$INSTALL_DIR")" ] && [ "$(id -u)" != "0" ]; then
    if command -v sudo >/dev/null 2>&1; then
      info "Installing to ${INSTALL_DIR} (requires sudo) ..."
      sudo=sudo
    else
      die "$INSTALL_DIR is not writable and sudo is unavailable. Set INSTALL_DIR to a writable path."
    fi
  else
    info "Installing to ${INSTALL_DIR} ..."
  fi
  $sudo mkdir -p "$INSTALL_DIR"
  $sudo install -m 0755 "$TMP/$BIN" "$INSTALL_DIR/$BIN"

  ok "Installed $("$INSTALL_DIR/$BIN" --version 2>/dev/null || echo "$BIN") to $INSTALL_DIR/$BIN"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) info "Add ${INSTALL_DIR} to your PATH:
    export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
  esac

  echo
  ok "Next: start the VPN service with"
  echo "    sudo ray up"
}

main "$@"
