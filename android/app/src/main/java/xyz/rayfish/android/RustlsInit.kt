package xyz.rayfish.android

import android.content.Context

/**
 * Bridges Android's system trust store into the Rust core's TLS stack.
 *
 * iroh's relay and discovery talk HTTPS (through reqwest and iroh-metrics),
 * which verify certificates with rustls-platform-verifier. On Android that
 * verifier reads the app's JavaVM and Context over JNI. Our .so is normally
 * loaded by JNA (via UniFFI), which does not register JNI native methods, so
 * we also load it with System.loadLibrary here and call the Rust-side init
 * once at startup. Without it, Node.start fails with "android context was not
 * initialized" and no network can connect.
 */
object RustlsInit {
    @Volatile
    private var done = false

    init {
        System.loadLibrary("ray_mobile")
    }

    /** Rust JNI export: Java_xyz_rayfish_android_RustlsInit_nativeInit. */
    private external fun nativeInit(context: Context)

    /** Registers the Android context with the TLS verifier exactly once. */
    @Synchronized
    fun ensureInitialized(context: Context) {
        if (done) return
        nativeInit(context.applicationContext)
        done = true
    }
}
