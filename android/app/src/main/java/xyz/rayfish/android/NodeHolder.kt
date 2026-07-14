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

    /** True once the daemon is built and not yet stopped. */
    val isStarted: Boolean get() = started

    // The user's persisted enable/disable intent. This is the authority for
    // whether the device should be online: the status poll must never start the
    // node on its own (that resurrects a node the user just disabled), so the
    // toggle records intent here and only explicit enable brings the node up.
    private const val PREFS_NAME = "rayfish_node"
    private const val KEY_ENABLED = "enabled"
    // Crash reporting is opt-out: on unless the user turns it off in You. See
    // [xyz.rayfish.android.Telemetry], which reads this to gate Sentry init.
    private const val KEY_CRASH_REPORTING = "crash_reporting"
    private const val KEY_INSTALL_ID = "install_id"
    // Auto-accept incoming file offers from the user's own paired devices. Default
    // on: sharing to one of your own devices lands the file with no manual tap. The
    // "own device" decision is made core-side from the device cert chain and
    // surfaced as FileOffer.own_device; this toggle is only the opt-out.
    private const val KEY_AUTO_ACCEPT_OWN = "auto_accept_own_devices"

    // Keep the control plane connected when the VPN tunnel is off, so file send
    // and receive keep working and the device stays visible in the mesh. Default
    // off: it holds a network connection open in the background. The motivating
    // case is running another VPN (Android allows only one VpnService at a time,
    // and our tunnel claims the same 100.64.0.0/10 range Tailscale uses), so the
    // tunnel goes away and only the data plane goes with it.
    private const val KEY_STAY_ONLINE = "stay_online"

    fun isEnabled(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, value: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, value).apply()
    }

    fun isAutoAcceptOwnDevices(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_AUTO_ACCEPT_OWN, true)

    fun setAutoAcceptOwnDevices(context: Context, value: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_AUTO_ACCEPT_OWN, value).apply()
    }

    fun isStayOnline(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_STAY_ONLINE, false)

    fun setStayOnline(context: Context, value: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_STAY_ONLINE, value).apply()
    }

    fun isCrashReportingEnabled(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_CRASH_REPORTING, true)

    fun setCrashReportingEnabled(context: Context, value: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_CRASH_REPORTING, value).apply()
    }

    /** Stable random id for this install, minted once and persisted. Tags every
     * diagnostics event so a device's events group together in Sentry. */
    fun installId(context: Context): String {
        val prefs = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_INSTALL_ID, null)?.let { return it }
        val id = java.util.UUID.randomUUID().toString()
        prefs.edit().putString(KEY_INSTALL_ID, id).apply()
        return id
    }

    /** Seed the device's default hostname from the Android model on first run,
     * so pairing auto-joins all use one consistent name. Idempotent: no-op once
     * a name is set. Runs on the caller's (IO) context; touches config only. */
    fun seedDeviceName(context: Context) {
        val node = get(context)
        val current = runCatching { node.defaultHostname() }.getOrDefault("")
        if (current.isNotBlank()) return
        val seed = sanitizeHostname(android.os.Build.MODEL ?: "")
        runCatching { node.setDefaultHostname(seed) }
    }

    /** Lowercase, keep [a-z0-9-], collapse/trim hyphens, cap 63, fall back to
     * "phone". Matches the core's is_valid_hostname rules. */
    private fun sanitizeHostname(raw: String): String {
        var s = raw.lowercase()
            .replace(Regex("[^a-z0-9-]"), "-")
            .replace(Regex("-+"), "-")
            .trim('-')
        if (s.length > 63) s = s.substring(0, 63).trim('-')
        return s.ifEmpty { "phone" }
    }

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
                seedDeviceName(context)
            }
            started = true
        }
    }

    /**
     * Fully stop the node so the device goes offline (control plane torn down,
     * not just the data plane). Clears the started flag so the next
     * [ensureStarted] rebuilds a fresh daemon. Safe to call when never started.
     */
    fun stopNode(context: Context) {
        synchronized(this) {
            runCatching { node?.stop() }
            started = false
        }
    }

    /**
     * Standby: tear the data plane down (TUN detached) but keep the control plane
     * connected, so files still flow and the device stays online in the mesh. This
     * is the mobile equivalent of desktop `ray down`.
     *
     * Deliberately does NOT clear [started]: the daemon stays built, so a later
     * enable is a plain Node.up(fd) with no rebuild (near-instant, like `ray up`).
     * No-op if the node was never started.
     */
    fun downNode(context: Context) {
        synchronized(this) {
            if (!started) return
            runCatching { node?.down() }
        }
    }
}
