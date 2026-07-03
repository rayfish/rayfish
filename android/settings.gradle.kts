import groovy.json.JsonSlurper
import java.io.File

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // On-disk Maven repo bundled inside the rustls-platform-verifier-android
        // crate. It ships the Kotlin AAR that rustls-platform-verifier calls over
        // JNI to reach Android's trust store (see RustlsInit / android_rustls).
        // cargo places the crate wherever it caches downloads, so locate it via
        // `cargo metadata` rather than hardcoding a path.
        maven {
            url = uri(rustlsPlatformVerifierMavenRepo())
            metadataSources { artifact() }
        }
    }
}

// Runs `cargo metadata` against ray-mobile (the crate that pulls in
// rustls-platform-verifier for Android) and returns the file:// URI of the
// bundled Maven repository inside rustls-platform-verifier-android.
fun rustlsPlatformVerifierMavenRepo(): String {
    val manifest = File(rootDir.parentFile, "ray-mobile/Cargo.toml")
    // Finder-launched Android Studio does not inherit the shell PATH, so cargo in
    // ~/.cargo/bin may be absent; invoke it by absolute path when present.
    val cargoBin = File(System.getProperty("user.home"), ".cargo/bin")
    val cargo = File(cargoBin, "cargo").let { if (it.exists()) it.absolutePath else "cargo" }

    val json = providers.exec {
        commandLine(
            cargo, "metadata", "--format-version", "1",
            "--filter-platform", "aarch64-linux-android",
            "--manifest-path", manifest.absolutePath,
        )
    }.standardOutput.asText.get()

    @Suppress("UNCHECKED_CAST")
    val packages = (JsonSlurper().parseText(json) as Map<String, Any>)["packages"] as List<Map<String, Any>>
    val pkg = packages.first { it["name"] == "rustls-platform-verifier-android" }
    val crateDir = File(pkg["manifest_path"] as String).parentFile
    return File(crateDir, "maven").toURI().toString()
}

rootProject.name = "rayfish-android"
include(":app")
