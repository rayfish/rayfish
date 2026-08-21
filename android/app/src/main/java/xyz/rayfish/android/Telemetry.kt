package xyz.rayfish.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import io.sentry.Attachment
import io.sentry.Sentry
import io.sentry.SentryLevel
import io.sentry.android.core.SentryAndroid

/**
 * Sentry crash reporting, gated by the user's opt-out toggle in the You screen.
 *
 * Sentry is initialized manually (not through the SDK's manifest auto-init) so
 * that [NodeHolder.isCrashReportingEnabled] is the only thing that decides
 * whether it runs. [apply] is called once at process start from
 * [RayfishApplication]; [enable]/[disable] are called when the toggle flips.
 */
object Telemetry {
    /** Initialize Sentry at startup only if crash reporting is left on. */
    fun apply(context: Context) {
        if (NodeHolder.isCrashReportingEnabled(context)) enable(context)
    }

    /** Turn crash reporting on. No-op if the DSN was not compiled in. */
    fun enable(context: Context) {
        val dsn = BuildConfig.SENTRY_DSN
        if (dsn.isBlank()) return
        SentryAndroid.init(context.applicationContext) { options ->
            options.dsn = dsn
            options.release = "rayfish-android@${BuildConfig.VERSION_NAME}"
            // The commit the APK was built from. Without it Sentry defaults dist
            // to versionCode, so every build of a version looks identical in the
            // dashboard and a report cannot be placed against a fix. See
            // rayGitSha in android/app/build.gradle.kts.
            options.dist = BuildConfig.GIT_SHA
            // Debug builds (the `.dev` package) report under the `dev`
            // environment so they don't mix into production telemetry.
            options.environment = if (BuildConfig.DEBUG) "dev" else "production"
            // Don't attach IPs, device names, or other personal data to events.
            options.isSendDefaultPii = false
            // Turn on Sentry structured logs so lines routed through
            // SentryLogcatAdapter (see RayfishVpnService) show up in the Logs
            // view on their own, not only as breadcrumbs on a crash.
            options.logs.isEnabled = true
        }
    }

    /** Turn crash reporting off: flush and shut the client down. */
    fun disable() {
        Sentry.close()
    }

    /** wifi / cellular / ethernet / other, from the active (non-VPN) network. */
    private fun transportType(context: Context): String {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return "unknown"
        val net = cm.activeNetwork ?: return "none"
        val caps = cm.getNetworkCapabilities(net) ?: return "unknown"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
    }

    /**
     * A node bring-up failure, reported without the user having to notice and
     * send diagnostics by hand. This is the one failure worth reporting on its
     * own: the node not starting means the device is offline in the mesh, with
     * no tunnel and no file transfer, and nothing in the UI says why.
     *
     * Throttled to one report per [FAILURE_REPORT_INTERVAL_MS] per process. Every
     * caller of NodeHolder.ensureStarted retries (the VPN service on each start
     * command, the UI poller, ShareActivity), so an un-throttled capture would
     * send the same failure on a loop.
     */
    fun captureStartFailure(context: Context, t: Throwable) {
        if (!Sentry.isEnabled()) return
        val now = SystemClock.elapsedRealtime()
        synchronized(this) {
            val last = lastFailureReportMs
            if (last != 0L && now - last < FAILURE_REPORT_INTERVAL_MS) return
            lastFailureReportMs = now
        }
        Sentry.withScope { scope ->
            scope.setTag("install_id", NodeHolder.installId(context))
            scope.setTag("transport", transportType(context))
            // The core's own log ring is the only place the reason lives: the
            // Kotlin exception says "start failed", the Rust log says what failed.
            runCatching {
                val logs = NodeHolder.get(context).logSnapshot()
                scope.addAttachment(Attachment(logs.toByteArray(), "rayfish-logs.txt", "text/plain"))
            }
            Sentry.captureException(t)
        }
    }

    private const val FAILURE_REPORT_INTERVAL_MS = 30 * 60 * 1000L

    @Volatile
    private var lastFailureReportMs = 0L

    /** Full log snapshot as a Sentry attachment. Returns the event id, or null
     * when Sentry is off / the send failed. Best-effort. */
    fun sendDiagnostics(context: Context): String? {
        if (!Sentry.isEnabled()) return null
        val node = NodeHolder.get(context)
        val logs = runCatching { node.logSnapshot() }.getOrDefault("")
        // Every report deliberately lands in one Sentry group. An earlier version
        // set a per-send fingerprint (a millisecond stamp) to split each click
        // into its own issue; it never actually split anything (488 reports in a
        // single group), and splitting was the wrong goal anyway. Diagnostics are
        // a mailbox, not a defect: hundreds of one-event issues would bury the
        // real crashes in the same queue. The tags below are what make a
        // particular report findable (`issue:<id> install_id:<uuid>`), and the
        // caller gets the event id back to quote.
        var id: String? = null
        Sentry.withScope { scope ->
            scope.setTag("install_id", NodeHolder.installId(context))
            scope.setTag("transport", transportType(context))
            scope.addAttachment(Attachment(logs.toByteArray(), "rayfish-logs.txt", "text/plain"))
            runCatching {
                val h = node.healthSnapshot()
                scope.setContexts("rayfish", mapOf(
                    "running" to h.running,
                    "networks" to h.networkCount.toLong(),
                    "peers_online" to h.peersOnline.toLong(),
                    "node_id" to h.nodeId,
                    "warn_count" to h.warnCount.toLong(),
                    "error_count" to h.errorCount.toLong(),
                ))
            }
            id = Sentry.captureMessage("rayfish diagnostics", SentryLevel.INFO).toString()
        }
        // captureMessage only enqueues; block briefly so a user-initiated report
        // is actually delivered before we tell them it was sent. Called off the
        // main thread (Dispatchers.IO in YouScreen).
        Sentry.flush(5000)
        return id
    }
}
