#!/bin/sh
set -euo pipefail
cd "$SRCROOT/.."
cargo -q build --release --locked -p rayfish --bin ray --features macos-app
destination="$TARGET_BUILD_DIR/$WRAPPER_NAME/Contents/MacOS/ray"
install -m 755 target/release/ray "$destination"
helpers="$TARGET_BUILD_DIR/$WRAPPER_NAME/Contents/Library/LaunchDaemons"
mkdir -p "$helpers"
install -m 644 macos/LaunchDaemons/com.rayfish.app.ssh.plist "$helpers/"
if [ "$CODE_SIGNING_ALLOWED" != "NO" ]; then
  codesign --force --options runtime --timestamp --sign "$EXPANDED_CODE_SIGN_IDENTITY" "$destination"
fi

