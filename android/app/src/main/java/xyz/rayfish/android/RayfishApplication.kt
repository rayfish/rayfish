package xyz.rayfish.android

import android.app.Application
import kotlin.concurrent.thread

/**
 * Process entry point. Runs before any activity or service, so it's where crash
 * reporting is brought up (subject to the user's opt-out) to catch failures that
 * happen during early startup.
 */
class RayfishApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Telemetry.apply(this)
        // Both of these touch the filesystem (prefs, and the previous process's
        // exit trace), so neither may run here on the main thread: Application
        // .onCreate is on the critical path of every launch, cold start and
        // system-restarted service alike.
        //
        // After Telemetry.apply, not before: the reporter sends through Sentry
        // and no-ops when the user has crash reporting turned off, which is only
        // decided once apply() has run.
        thread(name = "rayfish-startup", isDaemon = true) {
            runCatching { NodeHolder.warm(this) }
            runCatching { ExitInfoReporter.reportNewExits(this) }
        }
    }
}
