#!/bin/sh
# Builds the Rust core for the platform Xcode is building, as a static library
# the app and the tunnel link.
set -eu
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
# Xcode exports the iOS SDK; cargo's build scripts run on the Mac and must not see it.
unset SDKROOT
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
case "${PLATFORM_NAME:-iphonesimulator}" in
    iphonesimulator) target=aarch64-apple-ios-sim ;;
    iphoneos) target=aarch64-apple-ios ;;
    *) echo "unsupported platform $PLATFORM_NAME" >&2; exit 1 ;;
esac
cd "$(dirname "$0")/.."
cargo -q build --release --locked -p ray-mobile --lib --target "$target"
