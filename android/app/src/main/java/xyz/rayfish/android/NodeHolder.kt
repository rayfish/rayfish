package xyz.rayfish.android

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Node

/**
 * Process-wide holder for the single [Node] FFI object. Both the VPN service and
 * the UI talk to the same instance so `up`/`down`/`status`/`join` stay coherent.
 * The node owns a tokio runtime, so we build exactly one per process.
 */
object NodeHolder {
    @Volatile
    private var node: Node? = null

    fun get(context: Context): Node {
        val existing = node
        if (existing != null) return existing
        return synchronized(this) {
            node ?: Node(context.applicationContext.filesDir.path).also { node = it }
        }
    }

    private val startMutex = Mutex()

    @Volatile
    private var started = false

    /**
     * Starts the node exactly once for the process, however many callers race to
     * invoke this concurrently (e.g. the initial UI launch and a cold-start deep
     * link firing at the same time). Later callers just await the first start.
     */
    suspend fun ensureStarted(context: Context) {
        if (started) return
        startMutex.withLock {
            if (started) return@withLock
            withContext(Dispatchers.IO) {
                // Register Android's trust store before start(): building the
                // iroh endpoint sets up TLS, which fails without it.
                RustlsInit.ensureInitialized(context)
                get(context).start()
            }
            started = true
        }
    }
}
