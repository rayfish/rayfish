package xyz.rayfish.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Node

/**
 * A network callback received by [NodeHolder], counted before filtering.
 *
 * Which kind fires matters for battery, and the two halves are not comparable.
 * [AVAILABLE] and [LOST] mean the default network really changed, and are rare.
 * [LINK_PROPERTIES] and [CAPABILITIES] also fire on things the endpoint does not
 * care about: a signal-strength update, a revised link-bandwidth estimate, a
 * reordered DNS server list. On a cellular link those arrive continuously.
 *
 * Forwarded events request an endpoint refresh and wake the signed-record
 * pollers. Comparing raw callback counts with dispatched notifications shows
 * whether filtering and debouncing are keeping that work bounded.
 */
enum class NetworkEvent(val label: String) {
    AVAILABLE("available"),
    LOST("lost"),
    LINK_PROPERTIES("link properties changed"),
    CAPABILITIES("capabilities changed"),
}

/**
 * One window of network-callback activity, as returned by
 * [NodeHolder.takeNetworkChurn]. Counts are per window, not per process: reading
 * them resets them.
 */
data class NetworkChurn(
    /** Callbacks received, by kind. Every [NetworkEvent] is present, possibly 0. */
    val perEvent: Map<NetworkEvent, Long>,
    /**
     * Callbacks that survived the debounce and became a real `networkChanged()`.
     * Read against [callbacks] to measure filtering and debouncing. The field
     * name is retained for telemetry compatibility; iroh may skip a rebind when
     * its own interface comparison finds no change.
     */
    val rebinds: Long,
    /** How long the window covers, in milliseconds. */
    val windowMs: Long,
) {
    val callbacks: Long get() = perEvent.values.sum()

    /** Nothing happened in this window, so there is nothing worth reporting. */
    fun isQuiet(): Boolean = callbacks == 0L && rebinds == 0L

    /**
     * Merge two windows. [PeriodicDiagnostics] carries a window forward when it
     * was not worth reporting on its own, so a slow drip still accumulates into
     * a report instead of being discarded eight hours at a time.
     */
    operator fun plus(other: NetworkChurn): NetworkChurn = NetworkChurn(
        perEvent = NetworkEvent.entries.associateWith { (perEvent[it] ?: 0) + (other.perEvent[it] ?: 0) },
        rebinds = rebinds + other.rebinds,
        windowMs = windowMs + other.windowMs,
    )

    /** Flat `network_<kind>` -> count map for a report's context block. */
    fun asContext(): Map<String, Long> =
        perEvent.mapKeys { (event, _) -> "network_" + event.name.lowercase() } +
            mapOf("network_rebinds" to rebinds, "network_window_ms" to windowMs)
}

/**
 * Process-wide holder for the single [Node] FFI object. Both the VPN service and
 * the UI talk to the same instance so `up`/`down`/`status`/`join` stay coherent.
 * The node owns a tokio runtime, so we build exactly one per process.
 */
object NodeHolder {
    private const val TAG = "NodeHolder"

    @Volatile
    private var node: Node? = null

    fun get(context: Context): Node {
        val existing = node
        if (existing != null) return existing
        return synchronized(this) {
            node ?: Node(context.applicationContext.filesDir.path).also { node = it }
        }
    }

    @Volatile
    private var started = false

    /**
     * Whether the node has been started in this process. Distinct from the
     * user's enable/disable intent and from whether a tunnel is up: this is only
     * "is there a live daemon behind the FFI". An identity restore reads it to
     * decide whether to put the node back afterwards, which on a fresh install
     * it must not, since starting is what mints the key it is trying to replace.
     */
    fun isStarted(): Boolean = started

    // The user's persisted enable/disable intent. This is the authority for
    // whether the device should be online: the status poll must never start the
    // node on its own (that resurrects a node the user just disabled), so the
    // toggle records intent here and only explicit enable brings the node up.
    private const val PREFS_NAME = "rayfish_node"
    private const val KEY_ENABLED = "enabled"
    // Crash reporting is opt-out: on unless the user turns it off in You. See
    // [xyz.rayfish.android.Telemetry], which reads this to gate Sentry init.
    private const val KEY_CRASH_REPORTING = "crash_reporting"
    // Unattended diagnostics on a timer. Opt-in, and only ever consulted while
    // crash reporting is on, since it reports through the same Sentry client.
    // See [PeriodicDiagnostics].
    private const val KEY_PERIODIC_DIAGNOSTICS = "periodic_diagnostics"
    private const val KEY_INSTALL_ID = "install_id"
    // Auto-accept incoming file offers from the user's own paired devices. Default
    // on: sharing to one of your own devices lands the file with no manual tap. The
    // "own device" decision is made core-side from the device cert chain and
    // surfaced as FileOffer.own_device; this toggle is only the opt-out.
    private const val KEY_AUTO_ACCEPT_OWN = "auto_accept_own_devices"

    // Standby is now the default: disabling Rayfish drops the data plane (TUN,
    // VPN slot) but keeps the control plane connected, so file send and receive
    // keep working and the device stays visible in the mesh. The motivating case
    // is running another VPN (Android allows only one VpnService at a time), so
    // the tunnel goes away and only the data plane goes with it.
    //
    // This key is an escape hatch for a user who wants disabling Rayfish to take
    // the device fully offline instead. Default false (standby). This is a NEW
    // key, not a flip of the old "stay_online" pref (default false, opt-in
    // standby): a user who had already turned that on has a stored
    // stay_online = true, and flipping its default in place would silently hand
    // them the opposite of what they asked for. The old key is left unread and
    // unmigrated; any leftover stay_online value in an existing install's
    // SharedPreferences is inert.
    private const val KEY_GO_OFFLINE_WHEN_DISABLED = "go_offline_when_disabled"

    /**
     * The one prefs file this app uses. Held once rather than looked up per call:
     * the first getSharedPreferences in a process parses the XML off disk
     * synchronously, and several of the call sites below run on the main thread.
     */
    fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // The two flags [RayfishVpnService.onStartCommand] and onRevoke read on the
    // main thread, cached in memory.
    //
    // Worth being precise about what this does and does not buy, because the
    // obvious claim is wrong: it is NOT what keeps the disk read off the main
    // thread. Application.onCreate reads this same prefs file (crash reporting
    // has to be initialized before anything can crash), and getBoolean blocks on
    // the file's load latch, so the one synchronous load is already paid on the
    // main thread at process start, before any service can run. By the time
    // onStartCommand reads these, the framework's own cache is warm.
    //
    // What it does buy: the service paths stop depending on that ordering
    // holding, and [warm] gives the load a chance to happen on a background
    // thread first. A read that beats the warm-up falls through to disk and is
    // correct, just slower, so this is only ever an optimisation.
    //
    // Safe to cache because this process is the only writer (MODE_PRIVATE, single
    // process) and every write goes through the setters below, which update the
    // cache in the same call.
    @Volatile
    private var enabledCache: Boolean? = null

    @Volatile
    private var goOfflineCache: Boolean? = null

    /**
     * Load the main-thread-read prefs into memory. Does disk I/O, so call it off
     * the main thread; [RayfishApplication] does at process start. Idempotent.
     */
    fun warm(context: Context) {
        val p = prefs(context)
        enabledCache = p.getBoolean(KEY_ENABLED, false)
        goOfflineCache = p.getBoolean(KEY_GO_OFFLINE_WHEN_DISABLED, false)
    }

    fun isEnabled(context: Context): Boolean =
        enabledCache ?: prefs(context).getBoolean(KEY_ENABLED, false).also { enabledCache = it }

    fun setEnabled(context: Context, value: Boolean) {
        enabledCache = value
        prefs(context).edit().putBoolean(KEY_ENABLED, value).apply()
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

    fun isGoOfflineWhenDisabled(context: Context): Boolean =
        goOfflineCache
            ?: prefs(context).getBoolean(KEY_GO_OFFLINE_WHEN_DISABLED, false)
                .also { goOfflineCache = it }

    fun setGoOfflineWhenDisabled(context: Context, value: Boolean) {
        goOfflineCache = value
        prefs(context).edit().putBoolean(KEY_GO_OFFLINE_WHEN_DISABLED, value).apply()
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

    /**
     * Whether to send a diagnostics report on a timer without the user asking.
     * Opt-in (default false), and gated on crash reporting: turning that off
     * takes this with it, because the reports go through the same client.
     */
    fun isPeriodicDiagnosticsEnabled(context: Context): Boolean =
        isCrashReportingEnabled(context) &&
            context.applicationContext
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_PERIODIC_DIAGNOSTICS, false)

    fun setPeriodicDiagnosticsEnabled(context: Context, value: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_PERIODIC_DIAGNOSTICS, value).apply()
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
     * link firing at the same time). Later callers just wait for the first start.
     *
     * This function, [stopNode] and [downNode] all guard their work with the same
     * `synchronized(this)` monitor on this singleton, so a start can never
     * interleave with a stop or a down: one always finishes before the other
     * begins, whichever thread it runs on. That serialization is worth a blocked
     * thread rather than a suspended coroutine, so this switches to
     * [Dispatchers.IO] first and only then takes the monitor: the blocking
     * `node.start()` FFI call and the `synchronized` block it runs in both then
     * execute on a plain IO-pool thread, never on whatever dispatcher the caller
     * happened to be on (composables here call this from the main-thread
     * coroutine scope; suspending into IO before blocking keeps that safe).
     */
    suspend fun ensureStarted(context: Context) {
        if (started) return
        withContext(Dispatchers.IO) {
            synchronized(this@NodeHolder) {
                if (!started) {
                    try {
                        // Register Android's trust store before start(): building
                        // the iroh endpoint sets up TLS, which fails without it.
                        RustlsInit.ensureInitialized(context)
                        get(context).start()
                    } catch (t: Throwable) {
                        // A node that will not start leaves the device offline in
                        // the mesh with nothing in the UI to say why, and every
                        // caller here only logs and moves on. Report it (throttled,
                        // and only if crash reporting is on) so it is visible
                        // without the user having to send diagnostics by hand.
                        Log.e(TAG, "node start failed", t)
                        runCatching { Telemetry.captureStartFailure(context, t) }
                        throw t
                    }
                    seedDeviceName(context)
                    registerNetworkCallback(context)
                    started = true
                }
            }
        }
    }

    private val netScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var networkCallbacks: List<NetworkChangeCallback> = emptyList()

    /**
     * Per-kind callback counts and the rebinds they produced, since the last
     * [takeNetworkChurn]. Kept here rather than in the reporter because this is
     * the only place that sees the events; the reporter only drains them.
     *
     * Plain counters, no log line per event: the whole point is the case where
     * there are thousands of them in a window, and a log that large is both the
     * cost being measured and useless to read.
     */
    private val eventCounts: Map<NetworkEvent, AtomicLong> =
        NetworkEvent.entries.associateWith { AtomicLong() }

    private val rebindCount = AtomicLong()

    /** Start of the current counting window, `elapsedRealtime`. */
    private val churnWindowStart = AtomicLong(android.os.SystemClock.elapsedRealtime())

    /**
     * Read the counters and start a fresh window. Not atomic across all five
     * counters, so a callback landing mid-drain can be counted in either window.
     * That is fine for what this measures: the question is whether a window holds
     * tens of events or tens of thousands, and one event either side of the line
     * does not change the answer.
     */
    fun takeNetworkChurn(): NetworkChurn {
        val now = android.os.SystemClock.elapsedRealtime()
        val start = churnWindowStart.getAndSet(now)
        return NetworkChurn(
            perEvent = eventCounts.mapValues { (_, c) -> c.getAndSet(0) },
            rebinds = rebindCount.getAndSet(0),
            windowMs = (now - start).coerceAtLeast(0),
        )
    }

    /**
     * Forward default-network changes to the core. Android blocks netlink route
     * updates for apps, so the Rust side (netwatch) cannot see a Wi-Fi/cellular
     * switch or roam on its own: without this the endpoint keeps using dead
     * sockets until something rebuilds them (observed as hours of DNS resolve
     * timeouts, no relay, no mDNS announce, device invisible to the mesh).
     * Lives with the node's lifecycle, so it also covers standby, where the
     * control plane is the only thing running and nothing else would notice.
     * Capability callbacks are filtered before debouncing: bandwidth estimates
     * and signal strength do not warrant a refresh or a signed-record lookup.
     *
     * onAvailable/onLost alone are not enough, which is what made a phone that
     * had moved stay disconnected: the default Network object survives a Wi-Fi
     * roam between access points, a DHCP renew, an IPv6 prefix change and
     * captive-portal validation, so none of those fire either callback. They
     * fire onLinkPropertiesChanged / onCapabilitiesChanged instead, and the
     * addresses under the endpoint have changed all the same.
     */
    private fun registerNetworkCallback(context: Context) {
        if (networkCallbacks.isNotEmpty()) return
        val cm = context.applicationContext.getSystemService(ConnectivityManager::class.java)
        if (cm == null) return
        fun callback(source: String) = NetworkChangeCallback { event, network, changed ->
            eventCounts[event]?.incrementAndGet()
            if (changed) {
                Log.i(TAG, "$source network ${event.label} ($network); notifying core")
                scheduleNotify()
            }
        }
        val default = callback("default")
        val physical = callback("physical")
        // A VPN's addresses/routes can stay fixed while its Wi-Fi or cellular
        // underlay changes. Observe physical links too so filtering the VPN's
        // capabilities cannot hide a DHCP renew, DNS change or handover. This
        // is a passive listener, not a request to keep an extra radio online.
        val physicalNetworks = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val registered = mutableListOf<NetworkChangeCallback>()
        runCatching {
            cm.registerDefaultNetworkCallback(default)
            registered += default
            cm.registerNetworkCallback(physicalNetworks, physical)
            registered += physical
        }.onSuccess { networkCallbacks = registered.toList() }
            .onFailure {
                default.deactivate()
                physical.deactivate()
                registered.forEach { cb -> runCatching { cm.unregisterNetworkCallback(cb) } }
                synchronized(notifyLock) {
                    notifyJob?.cancel()
                    notifyJob = null
                }
                Log.w(TAG, "network callback registration failed", it)
            }
    }

    /**
     * Coalesce a burst of callbacks into one rebind. A single network switch
     * fires several of them within a few hundred milliseconds (available, then
     * capabilities, then link properties, often more than once as validation
     * completes), and each networkChanged() requests an endpoint refresh and
     * wakes signed-record polling. The last one sees the settled
     * addresses, so waiting for the burst to stop is both cheaper and more
     * accurate than acting on the first.
     *
     * The delay also keeps this off Android's connectivity thread, which the FFI
     * call must never block.
     */
    private const val NETWORK_DEBOUNCE_MS = 400L

    /**
     * Guards [notifyJob] only. Deliberately not this object's own monitor: these
     * callbacks arrive on Android's connectivity thread, and [ensureStarted] /
     * [stopNode] hold that monitor across blocking FFI calls, so sharing it would
     * park a system thread behind a node start.
     */
    private val notifyLock = Any()

    private var notifyJob: Job? = null

    private fun scheduleNotify() {
        synchronized(notifyLock) {
            notifyJob?.cancel()
            notifyJob = netScope.launch {
                delay(NETWORK_DEBOUNCE_MS)
                // Counted here, past the debounce, so this is rebinds actually
                // dispatched rather than callbacks received. A cancelled job
                // never reaches this line, which is the coalescing being
                // measured.
                rebindCount.incrementAndGet()
                runCatching { node?.networkChanged() }
            }
        }
    }

    private fun unregisterNetworkCallback(context: Context) {
        val callbacks = networkCallbacks
        networkCallbacks = emptyList()
        callbacks.forEach { it.deactivate() }
        synchronized(notifyLock) {
            notifyJob?.cancel()
            notifyJob = null
        }
        val cm = context.applicationContext.getSystemService(ConnectivityManager::class.java)
        callbacks.forEach { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }
    }

    /**
     * Fully stop the node so the device goes offline (control plane torn down,
     * not just the data plane). Clears the started flag so the next
     * [ensureStarted] rebuilds a fresh daemon. Safe to call when never started.
     *
     * The reset calls below deliberately run after the monitor is released:
     * [TransferNotifier.reset], [OfferNotifier.reset] and [FileAutoAccept.reset]
     * take their own locks, and none of them is ever called from inside this
     * object's monitor, so there is no path back into this monitor from theirs
     * to deadlock against.
     */
    fun stopNode(context: Context) {
        synchronized(this) {
            unregisterNetworkCallback(context)
            runCatching { node?.stop() }
            started = false
        }
        // The core's transfer and file-offer ids both restart at 1 on the next
        // start(); reset the process-wide bookkeeping for each so a later
        // transfer or offer landing on a reused id is never muted (or, for a
        // given-up offer, wrongly left un-hidden) by a stale entry.
        TransferNotifier.reset(context)
        OfferNotifier.reset(context)
        FileAutoAccept.reset()
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
