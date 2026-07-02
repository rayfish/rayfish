import org.gradle.internal.os.OperatingSystem
import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "xyz.rayfish.android"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "xyz.rayfish.android"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // ray-mobile only builds these two ABIs for now (device + emulator).
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // The JNA aar and the generated .so both land under jniLibs; keep them.
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // UniFFI-generated Kotlin bindings use JNA to load libray_mobile.so.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}

// --- Rust / cargo-ndk integration -----------------------------------------
// Builds libray_mobile.so for both ABIs straight into the jniLibs source set so
// the APK packages them. Requires cargo-ndk + the android rust targets on PATH.

val repoRoot = rootDir.parentFile
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")

val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Cross-compile ray-mobile into src/main/jniLibs for each ABI"
    workingDir = repoRoot

    val ndkHome = System.getenv("ANDROID_NDK_HOME")
        ?: "${System.getenv("ANDROID_HOME") ?: "${System.getProperty("user.home")}/Library/Android/sdk"}/ndk/27.2.12479018"
    environment("ANDROID_NDK_HOME", ndkHome)

    // Android Studio launched from the Dock/Finder does not inherit the shell
    // PATH, so `cargo` / `cargo-ndk` in ~/.cargo/bin aren't found. Invoke cargo
    // by absolute path when present, and prepend ~/.cargo/bin to the task's PATH
    // so cargo can locate its `cargo-ndk` subcommand too.
    val cargoBin = File(System.getProperty("user.home"), ".cargo/bin")
    val cargoExe = if (OperatingSystem.current().isWindows) "cargo.exe" else "cargo"
    val cargo = File(cargoBin, cargoExe).let { if (it.exists()) it.absolutePath else cargoExe }
    val sep = File.pathSeparator
    environment("PATH", "${cargoBin.absolutePath}$sep${System.getenv("PATH") ?: ""}")

    // Built in release so the shipped .so is stripped and small (see the
    // root Cargo.toml `[profile.release]` strip setting). For a debug native
    // build with symbols, run `cargo ndk ... build` by hand without `--release`.
    commandLine(
        cargo, "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", jniLibsDir.asFile.absolutePath,
        "build",
        "--release",
        "-p", "ray-mobile",
    )

    // ray-mobile statically links iroh/irpc into libray_mobile.so; cargo-ndk
    // still drops their standalone cdylib artifacts (libiroh*.so, libirpc*.so)
    // into jniLibs alongside it. Nothing loads those at runtime, so prune
    // everything except our own lib to keep them out of the APK.
    doLast {
        jniLibsDir.asFile.walkBottomUp()
            .filter { it.isFile && it.name.endsWith(".so") && it.name != "libray_mobile.so" }
            .forEach { it.delete() }
    }
}

tasks.named("preBuild").configure {
    dependsOn(cargoNdkBuild)
}
