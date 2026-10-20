#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
xcrun devicectl list devices --json-output "$work/devices.json" >/dev/null
device=$(python3 - "$work/devices.json" "${1:-${IOS_DEVICE:-}}" <<'PYTHON'
import json
import sys

with open(sys.argv[1]) as source:
    devices = json.load(source)["result"]["devices"]
requested = sys.argv[2]
candidates = []
for device in devices:
    properties = device.get("properties", {})
    hardware = properties.get("hardware", device.get("hardwareProperties", {}))
    connection = properties.get("connection", device.get("connectionProperties", {}))
    state = properties.get("state", device.get("deviceProperties", {}))
    if hardware.get("platform") != "iOS" or hardware.get("reality") != "physical":
        continue
    if requested:
        if requested not in (device["identifier"], hardware.get("udid"), state.get("name")):
            continue
    elif connection.get("state", connection.get("tunnelState")) != "connected":
        continue
    candidates.append(hardware["udid"])
if len(candidates) != 1:
    sys.exit("Connect and unlock one iPhone, or select one with just ios-run DEVICE.")
print(candidates[0])
PYTHON
)

# Use the local development certificate's team unless one was supplied.
team=${IOS_TEAM_ID:-}
if [[ -z "$team" ]]; then
    team=$(security find-certificate -c 'Apple Development' -p |
        openssl x509 -noout -subject -nameopt multiline |
        sed -n 's/^ *organizationalUnitName *= *//p' || true)
fi
if ! [[ "$team" =~ ^[A-Z0-9]{10}$ ]]; then
    echo 'Set IOS_TEAM_ID to your Apple development team ID.' >&2
    exit 1
fi

xcodegen generate --quiet --spec ios/project.yml --project ios
xcodebuild -quiet -project ios/Rayfish.xcodeproj -scheme Rayfish \
    -configuration Debug -destination "id=$device" -derivedDataPath target/ios-device \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
    CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$team" \
    RAYFISH_GIT_SHA="$(git rev-parse --short HEAD)" build
app=target/ios-device/Build/Products/Debug-iphoneos/Rayfish.app
bundle=xyz.rayfish.ios

xcrun devicectl device install app --device "$device" "$app"
xcrun devicectl device process launch --terminate-existing --device "$device" "$bundle"
