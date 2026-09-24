#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo 'Usage: bash scripts/package-macos-dmg.sh <Rayfish.app> <output.dmg>' >&2
    exit 1
fi
command -v create-dmg >/dev/null || {
    echo 'Install the DMG packager with: brew install create-dmg' >&2
    exit 1
}
app=$1
dmg=$2
[[ -d "$app/Contents" && ! -e "$dmg" ]]
root=$(cd "$(dirname "$0")/.." && pwd)
staging=$(mktemp -d "${TMPDIR:-/tmp}/rayfish-dmg.XXXXXX")
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/content" "$(dirname "$dmg")"
ditto "$app" "$staging/content/Rayfish.app"
xcrun swift "$root/macos/Installer/Background.swift" "$root" "$staging/background.tiff"

create-dmg \
    --volname 'Install Rayfish' \
    --volicon "$app/Contents/Resources/AppIcon.icns" \
    --background "$staging/background.tiff" \
    --window-pos 200 120 --window-size 720 508 \
    --icon-size 96 --text-size 13 \
    --icon Rayfish.app 200 275 --hide-extension Rayfish.app \
    --app-drop-link 520 275 \
    "$dmg" "$staging/content"
