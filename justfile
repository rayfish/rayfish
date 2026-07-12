target := "x86_64-unknown-linux-gnu"
musl_target := "x86_64-unknown-linux-musl"
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
    cargo -q run -p ray-mobile --bin uniffi-bindgen -- generate --library target/debug/libray_mobile.{{lib_ext}} --language kotlin --out-dir android/app/src/main/java
    cd android && ./gradlew :app:assembleDebug
    @echo "APK: android/app/build/outputs/apk/debug/app-debug.apk"

release:
    cargo -q build --release

fmt:
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    # cargo shear --fix # cargo install shear

cross:
    cross -q build --release --target {{target}}

# Static musl build: one binary that runs on any Linux regardless of glibc
# version (deps are musl-clean: ring + hickory, no C/dlopen dependencies).
cross-musl:
    cross -q build --release --target {{musl_target}}

# Build both the glibc and static-musl release binaries.
cross-all: cross cross-musl

deploy ip:
    cross -q build --release --target {{target}}
    just scp {{ip}}

# Copy an already-built release binary to a host + (re)start the daemon. No build.
# Use after `just cross` when deploying the same binary to several hosts.
scp ip:
    rsync -az --progress target/{{target}}/release/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}}"

deploy-dev ip:
    cross -q build --target {{target}}
    just scp-dev {{ip}}

# Debug counterpart of `scp`: copy an already-built debug binary, no build.
scp-dev ip:
    rsync -az --progress target/{{target}}/debug/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}} (debug build)"

check:
    cargo -q check

run *args:
    sudo cargo -q run -- {{args}}

# Exit-node kernel plumbing test: runs the real `nft` / `ip rule` code paths and
# asserts the resulting kernel state. Needs Linux + root + a mutable netns, so it
# runs in a throwaway privileged container (never against your own routing table).
# Builds the test binary with cross, then executes it under docker.
e2e-kernel:
    cross -q test --target {{target}} --test exit_node_kernel --no-run
    #!/usr/bin/env bash
    set -euo pipefail
    BIN=$(find target/{{target}}/debug/deps -name 'exit_node_kernel-*' -type f -perm -u+x | head -1)
    [ -n "$BIN" ] || { echo "test binary not found"; exit 1; }
    echo "running $BIN in a privileged container"
    docker run --rm --privileged --network host \
      -v "$PWD/$BIN:/exit_node_kernel:ro" \
      -e RAYFISH_KERNEL_TEST=1 \
      ubuntu:22.04 \
      bash -c 'apt-get update -qq && apt-get install -y -qq nftables iproute2 >/dev/null && /exit_node_kernel --test-threads=1 --nocapture'
