#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools_dir="$repo_root/target/tools"
formatter="$tools_dir/ktlint-1.8.0"

if [ ! -f "$formatter" ]; then
    mkdir -p "$tools_dir"
    download=$(mktemp "$tools_dir/ktlint.XXXXXX")
    trap 'rm -f "$download"' EXIT
    curl -fsSL --retry 3 https://github.com/ktlint/ktlint/releases/download/1.8.0/ktlint -o "$download"
    actual_hash=$(shasum -a 256 "$download" | cut -d ' ' -f 1)
    expected_hash=a3fd620207d5c40da6ca789b95e7f823c54e854b7fade7f613e91096a3706d75
    [ "$actual_hash" = "$expected_hash" ] || { echo 'ktlint download checksum mismatch' >&2; exit 1; }
    chmod +x "$download"
    mv "$download" "$formatter"
    trap - EXIT
fi

"$formatter" --format --ignore-autocorrect-failures \
    "$repo_root/android/app/src/main/java/uniffi/ray_mobile/ray_mobile.kt"
