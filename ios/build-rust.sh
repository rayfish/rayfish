#!/bin/sh
# Builds the Rust core for the platform Xcode is building, as a static library
# the app and the tunnel link.
set -eu
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
# Xcode exports the iOS SDK and IPHONEOS_DEPLOYMENT_TARGET. The deployment
# target reaches the C code built into the library; the SDK must not, since
# cargo's build scripts run on the Mac.
unset SDKROOT
case "${PLATFORM_NAME:-iphonesimulator}" in
    iphonesimulator) target=aarch64-apple-ios-sim ;;
    iphoneos) target=aarch64-apple-ios ;;
    *) echo "unsupported platform $PLATFORM_NAME" >&2; exit 1 ;;
esac
cd "$(dirname "$0")/.."
cargo -q build --release --locked -p ray-mobile --lib --target "$target"
