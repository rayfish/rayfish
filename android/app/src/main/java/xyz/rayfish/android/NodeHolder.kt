package xyz.rayfish.android

import android.content.Context
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
}
