package xyz.rayfish.android

import android.content.Context
import io.sentry.Sentry
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
}
