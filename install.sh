#!/bin/sh
#
# Rayfish installer. Installs the `ray` binary from the latest GitHub release.
#
#   curl -fsSL https://rayfish.xyz/install.sh | sh
#
# Options (env vars):
#   INSTALL_DIR   target dir (default: /usr/local/bin)
#   RAY_VERSION   pin a release tag, e.g. v0.1.0 (default: latest)
#
# POSIX sh: this is piped to `sh`, which is dash on most Linux distros and does
# not support bash-only options like `set -o pipefail`.
set -eu

REPO="rayfish/rayfish"
BIN="ray"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${RAY_VERSION:-latest}"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { printf "${BLUE}%s${NC}\n" "$*"; }
ok()    { printf "${GREEN}%s${NC}\n" "$*"; }
err()   { printf "${RED}%s${NC}\n" "$*" >&2; }
die()   { err "$*"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need curl

# Lowest glibc the gnu Linux binaries are built against (CI runs on
# ubuntu-22.04 = glibc 2.35). A host below this can't run the gnu build.
GLIBC_MIN="2.35"

# Sets the globals OS and ASSET (base asset name, no libc suffix); call directly.
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

# Base URL for the chosen release (latest → the redirecting "latest" path).
release_base() {
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/${REPO}/releases/latest/download"
  else
    echo "https://github.com/${REPO}/releases/download/${VERSION}"
  fi
}

verify_sha256() {
  local file="$1" sha_file="$2" expected actual
  expected="$(cut -d' ' -f1 < "$sha_file")"
  [ -n "$expected" ] || { info "no checksum published; skipping verification"; return 0; }
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
  else
    actual="$(shasum -a 256 "$file" | cut -d' ' -f1)"
  fi
  [ "$actual" = "$expected" ] || die "checksum mismatch
  expected: $expected
  got:      $actual"
  ok "checksum verified"
}

main() {
  local asset base url
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
  else
    info "no .sha256 sidecar found; skipping verification"
  fi

  chmod +x "$TMP/$BIN"

  # Install. Use sudo when the target dir isn't writable by the current user.
  local sudo=""
  if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" != "0" ]; then
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

  ok "Installed $($INSTALL_DIR/$BIN --version 2>/dev/null || echo "$BIN") to $INSTALL_DIR/$BIN"

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
