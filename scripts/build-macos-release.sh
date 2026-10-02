#!/usr/bin/env bash
set -euo pipefail

: "${MACOS_ARCH:?Set MACOS_ARCH to arm64 or x86_64}"
: "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID}"
: "${RAYFISH_APP_PROFILE:?Set the app distribution profile UUID or name}"
: "${RAYFISH_TUNNEL_PROFILE:?Set the tunnel distribution profile UUID or name}"
: "${GITHUB_RUN_NUMBER:?Run this script through the macOS app release workflow}"

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != "$MACOS_ARCH" ]]; then
    echo 'Build each architecture on a matching macOS runner.' >&2
    exit 1
fi

version=$(cargo metadata --locked --no-deps --format-version 1 |
    jq -er '.packages[] | select(.name == "rayfish") | .version')
if [[ -n "${RELEASE_TAG:-}" ]]; then
    [[ "$RELEASE_TAG" == "v$version" ]] || {
        echo 'Release tag must match the rayfish Cargo version.' >&2
        exit 1
    }
    if [[ "${RELEASE_FROM_MASTER:-false}" != true ]]; then
        [[ "$(git rev-parse "refs/tags/$RELEASE_TAG^{commit}")" == "$(git rev-parse HEAD)" ]] || {
            echo 'Release tag must point to the commit being built.' >&2
            exit 1
        }
    fi
fi
# CFBundleShortVersionString is numeric, even for a prerelease tag.
marketing_version=${version%%[-+]*}
[[ "$marketing_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
output="$PWD/target/macos-release"
mkdir -p "$output"
xcodegen generate --spec macos/project.yml --project macos
xcodebuild -quiet \
    -project macos/Rayfish.xcodeproj -scheme Rayfish -configuration Release \
    -destination "platform=macOS,arch=$MACOS_ARCH" \
    -derivedDataPath "$output/build" \
    ARCHS="$MACOS_ARCH" ONLY_ACTIVE_ARCH=YES \
    DEVELOPMENT_TEAM="$APPLE_TEAM_ID" \
    RAYFISH_APP_PROFILE="$RAYFISH_APP_PROFILE" \
    RAYFISH_TUNNEL_PROFILE="$RAYFISH_TUNNEL_PROFILE" \
    RAYFISH_UPDATE_FEED="https://github.com/rayfish/rayfish/releases/latest/download/Rayfish-appcast-$MACOS_ARCH.xml" \
    MARKETING_VERSION="$marketing_version" \
    CURRENT_PROJECT_VERSION="$((1000 + GITHUB_RUN_NUMBER))" \
    build 2>&1 | tee "$output/build.log"

app="$output/build/Build/Products/Release/Rayfish.app"
sparkle="$app/Contents/Frameworks/Sparkle.framework"
[[ -d "$sparkle" ]] || {
    echo 'Sparkle framework is missing from the release app.' >&2
    exit 1
}
# Xcode signs the copied framework but leaves its bundled helpers ad hoc signed.
# Sign from the inside out so each enclosing signature includes its signed contents.
sparkle_version="$sparkle/Versions/B"
signing_identity='Developer ID Application'
codesign --force --options runtime --timestamp --sign "$signing_identity" \
    "$sparkle_version/XPCServices/Installer.xpc"
codesign --force --options runtime --timestamp --preserve-metadata=entitlements \
    --sign "$signing_identity" "$sparkle_version/XPCServices/Downloader.xpc"
codesign --force --options runtime --timestamp --sign "$signing_identity" \
    "$sparkle_version/Autoupdate"
codesign --force --options runtime --timestamp --sign "$signing_identity" \
    "$sparkle_version/Updater.app"
codesign --force --options runtime --timestamp --sign "$signing_identity" "$sparkle"
codesign --force --options runtime --timestamp --preserve-metadata=entitlements \
    --sign "$signing_identity" "$app"
codesign --verify --deep --strict "$app"
for binary in "$app/Contents/MacOS/Rayfish" "$app/Contents/MacOS/ray" \
    "$app/Contents/Library/SystemExtensions/com.rayfish.app.tunnel.systemextension/Contents/MacOS/com.rayfish.app.tunnel"; do
    lipo "$binary" -verify_arch "$MACOS_ARCH"
done
just macos-validate "$app"
"$app/Contents/MacOS/ray" --version
"$app/Contents/MacOS/ray" status --help
echo "MACOS_RELEASE_VERSION=$version" >> "$GITHUB_ENV"
echo "MACOS_DMG_LABEL=$version" >> "$GITHUB_ENV"
