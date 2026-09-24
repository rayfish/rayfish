target := "x86_64-unknown-linux-gnu"
musl_target := "x86_64-unknown-linux-musl"
# Cross builds keep their own target dir, for the same reason `android-check`
# does: the cross image (Ubuntu 22.04) cannot execute build scripts a modern
# host compiled, so sharing `target/` fails on a glibc version mismatch the
# moment anyone runs a native `just release` first.
cross_dir := "target/cross"
binary := "ray"
user := "root"

# Host cdylib extension for the UniFFI bindgen `--library` input.
lib_ext := if os() == "macos" { "dylib" } else { "so" }

# Build the Rust workspace and the Android APK.
build: apk
    cargo -q build

# Needs cargo-ndk, the android rust targets, and a JDK 17 (set JAVA_HOME if the
# `java` on PATH isn't 17). Gradle only rebuilds the .so, so we regen bindings.

# Regenerate the UniFFI Kotlin bindings and assemble the Android debug APK.
apk:
    cargo -q build -p ray-mobile
    cargo -q run -p ray-mobile --bin uniffi-bindgen -- generate --library target/debug/libray_mobile.{{lib_ext}} --language kotlin --out-dir android/app/src/main/java --no-format
    sh scripts/format-generated-kotlin.sh
    cd android && ./gradlew :app:assembleDebug
    @echo "APK: android/app/build/outputs/apk/debug/app-debug.apk"

# The sibling repos in this tree name this recipe `android`, so accept both.
alias android := apk

# Generate and open the native macOS app project. The app needs normal Xcode
# signing configuration before its system extension can run on a local Mac.
macos:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "$(uname)" != "Darwin" ]; then
        echo "just macos must run on macOS" >&2
        exit 1
    fi
    if ! command -v xcodegen >/dev/null; then
        if ! command -v brew >/dev/null; then
            echo "XcodeGen is required. Install Homebrew, then run just macos again." >&2
            exit 1
        fi
        brew install xcodegen
    fi
    xcodegen generate --spec macos/project.yml --project macos
    open macos/Rayfish.xcodeproj

# Test macOS legacy-service detection and migration without touching launchd.
macos-test:
    mkdir -p target/macos-tests
    xcrun swiftc macos/Shared/LegacyDaemon.swift macos/Tests/LegacyDaemonTests.swift -o target/macos-tests/migration-tests
    target/macos-tests/migration-tests

# Exercise concurrent XPC clients, signature rejection, and request timeouts.
macos-ipc-test identity="Apple Development":
    mkdir -p target/macos-tests
    xcrun swiftc -parse-as-library macos/Shared/TunnelIPC.swift macos/Shared/ProviderMessage.swift macos/Tests/TunnelIPCTests.swift -o target/macos-tests/tunnel-ipc-tests
    codesign --force --sign "{{identity}}" --identifier com.rayfish.app target/macos-tests/tunnel-ipc-tests
    target/macos-tests/tunnel-ipc-tests

# Build a locally testable app with automatic Apple Development signing.
macos-dev:
    env CARGO_PROFILE_RELEASE_STRIP=none xcodebuild -quiet -project macos/Rayfish.xcodeproj -scheme Rayfish -configuration Debug -destination platform=macOS,arch=arm64 ARCHS=arm64 -derivedDataPath target/macos-development -allowProvisioningUpdates -allowProvisioningDeviceRegistration build

# Check the actual signed release before installing it.
macos-validate app="target/macos/Build/Products/Release/Rayfish.app":
    xcrun swift macos/Tests/ValidateBundle.swift "{{app}}"

# Require Apple notarization before handing over a release for installation.
macos-assess app="target/macos/Build/Products/Release/Rayfish.app":
    spctl --assess --type execute --verbose=2 "{{app}}"
    codesign --verify --strict -R='notarized' "{{app}}/Contents/Library/SystemExtensions/com.rayfish.app.tunnel.systemextension"

# Compile the Android core for both APK ABIs without an NDK on this machine:
# cross builds it in a container (see cross/Dockerfile.android). Catches the
# `#[cfg(target_os = "android")]` code that no desktop build ever sees. `just
# apk` is still what produces an installable APK.
#
# The target dir is separate on purpose: cross's Android images are old enough
# (Ubuntu 16.04) that they cannot execute build scripts a modern host compiled,
# and sharing `target/` would have each run rebuild what the other just cached.
android-check:
    CARGO_TARGET_DIR=target/android cross -q build -p ray-mobile --target aarch64-linux-android
    CARGO_TARGET_DIR=target/android cross -q build -p ray-mobile --target x86_64-linux-android

release:
    cargo -q build --release

fmt:
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    # cargo shear --fix # cargo install shear

# Format only the .rs files you have actually touched (modified or new).
#
# Use this mid-change instead of `just fmt`. `cargo fmt` always formats the
# whole crate, and `cargo fmt -- some/file.rs` does NOT narrow it: cargo passes
# every target to rustfmt and appends your paths, so unrelated files get
# rewritten and land in your diff. Calling rustfmt directly is the only way to
# scope it.
fmt-changed:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$({ git diff --name-only HEAD -- '*.rs'; \
              git ls-files --others --exclude-standard -- '*.rs'; } | sort -u)
    if [ -z "$files" ]; then echo "no changed .rs files"; exit 0; fi
    echo "$files"
    # shellcheck disable=SC2086
    rustfmt --edition 2024 $files

cross:
    CARGO_TARGET_DIR={{cross_dir}} cross -q build --release --target {{target}}

# Static musl build: one binary that runs on any Linux regardless of glibc
# version (deps are musl-clean: ring + hickory, no C/dlopen dependencies).
cross-musl:
    CARGO_TARGET_DIR={{cross_dir}} cross -q build --release --target {{musl_target}}

# Build both the glibc and static-musl release binaries.
cross-all: cross cross-musl

# The restart is not redundant: with the service already running, `ray up` is
# only an IPC call, so it neither re-execs the new binary nor applies a
# start-time setting like ipv6-only. `up` first (it installs the unit when it
# is missing, and persists the flags), then restart onto the new binary.

# Install this checkout as the local daemon (args go to `ray up`, e.g. --ipv6-only).
local-dev *args:
    cargo -q build --release
    sudo install -m 755 target/release/{{binary}} /usr/local/bin/{{binary}}
    sudo {{binary}} up {{args}}
    sudo {{binary}} restart
    @echo "Installed /usr/local/bin/{{binary}} and restarted the local daemon"

deploy ip:
    CARGO_TARGET_DIR={{cross_dir}} cross -q build --release --target {{target}}
    just scp {{ip}}

# Copy an already-built release binary to a host + (re)start the daemon. No build.
# Use after `just cross` when deploying the same binary to several hosts.
scp ip:
    rsync -az --progress {{cross_dir}}/{{target}}/release/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}}"

deploy-dev ip:
    CARGO_TARGET_DIR={{cross_dir}} cross -q build --target {{target}}
    just scp-dev {{ip}}

# Debug counterpart of `scp`: copy an already-built debug binary, no build.
scp-dev ip:
    rsync -az --progress {{cross_dir}}/{{target}}/debug/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}} (debug build)"

check:
    cargo -q check

run *args:
    sudo cargo -q run -- {{args}}
