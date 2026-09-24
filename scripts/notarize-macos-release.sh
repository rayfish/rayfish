#!/usr/bin/env bash
set -euo pipefail

: "${MACOS_ARCH:?Set MACOS_ARCH}"
: "${MACOS_RELEASE_VERSION:?Build the release app first}"
: "${APPLE_API_PRIVATE_KEY:?Set the App Store Connect team API private key}"
: "${APPLE_API_KEY_ID:?Set the API key ID}"
: "${APPLE_API_ISSUER_ID:?Set the API issuer ID}"
: "${RUNNER_TEMP:?Run this script through the macOS app release workflow}"

output="$PWD/target/macos-release"
app="$output/build/Build/Products/Release/Rayfish.app"
key="$RUNNER_TEMP/notary-key.p8"
umask 077
printf '%s' "$APPLE_API_PRIVATE_KEY" > "$key"
trap 'rm -f "$key"' EXIT
umask 022

notarize() {
    local file=$1 label=$2 result status submission
    result="$output/notary-$label.json"
    status=0
    xcrun notarytool submit "$file" --key "$key" --key-id "$APPLE_API_KEY_ID" \
        --issuer "$APPLE_API_ISSUER_ID" --wait --timeout 30m \
        --output-format json > "$result" || status=$?
    submission=$(jq -r '.id // empty' "$result")
    if [[ -n "$submission" ]]; then
        echo "Notarization $label submission: $submission"
        xcrun notarytool log "$submission" --key "$key" --key-id "$APPLE_API_KEY_ID" \
            --issuer "$APPLE_API_ISSUER_ID" "$output/notary-$label-log.json" || true
    fi
    if [[ "$status" != 0 ]] || ! jq -e '.status == "Accepted"' "$result" >/dev/null; then
        echo "Notarization of $label was not accepted. See the diagnostics artifact." >&2
        return 1
    fi
}

ditto -c -k --keepParent "$app" "$output/Rayfish.zip"
notarize "$output/Rayfish.zip" app
xcrun stapler staple "$app"
xcrun stapler validate "$app"
just macos-assess "$app"

mkdir -p "$output/dist"
dmg="$output/dist/Rayfish-${MACOS_DMG_LABEL:-$MACOS_RELEASE_VERSION}-$MACOS_ARCH.dmg"
bash scripts/package-macos-dmg.sh "$app" "$dmg"
codesign --sign 'Developer ID Application' --timestamp "$dmg"
notarize "$dmg" dmg
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
codesign --verify --strict "$dmg"
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
cd "$output/dist"
shasum -a 256 "${dmg##*/}" > "${dmg##*/}.sha256"
