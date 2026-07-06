package xyz.rayfish.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
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

    /** Full log snapshot as a Sentry attachment. Returns the event id, or null
     * when Sentry is off / the send failed. Best-effort. */
    fun sendDiagnostics(context: Context): String? {
        if (!Sentry.isEnabled()) return null
        val node = NodeHolder.get(context)
        val logs = runCatching { node.logSnapshot() }.getOrDefault("")
        // A per-send stamp so each report is its own Sentry issue instead of
        // folding into one group. Without it every "Send diagnostics" click
        // reuses the same message and only bumps the existing issue's count, so
        // repeat sends look like nothing happened.
        val stamp = System.currentTimeMillis().toString()
        var id: String? = null
        Sentry.withScope { scope ->
            scope.setTag("install_id", NodeHolder.installId(context))
            scope.setTag("transport", transportType(context))
            scope.setFingerprint(listOf("rayfish-diagnostics", stamp))
            scope.addAttachment(Attachment(logs.toByteArray(), "rayfish-logs.txt", "text/plain"))
            runCatching {
                val h = node.healthSnapshot()
                scope.setContexts("rayfish", mapOf(
                    "running" to h.running,
                    "networks" to h.networkCount.toLong(),
                    "peers_online" to h.peersOnline.toLong(),
                    "node_id" to h.nodeId,
                    "mesh_ipv4" to h.meshIpv4,
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
