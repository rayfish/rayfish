target := "x86_64-unknown-linux-gnu"
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

cross:
    cross -q build --release --target {{target}}

deploy ip:
    cross -q build --release --target {{target}}
    rsync -az --progress target/{{target}}/release/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}}"

deploy-dev ip:
    cross -q build --target {{target}}
    rsync -az --progress target/{{target}}/debug/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group rayfish >/dev/null || groupadd rayfish && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && (systemctl restart rayfish 2>/dev/null || {{binary}} up)"
    @echo "Deployed and installed daemon on {{ip}} (debug build)"

check:
    cargo -q check

run *args:
    sudo cargo -q run -- {{args}}
