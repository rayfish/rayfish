package xyz.rayfish.android

import android.app.Application

/**
 * Process entry point. Runs before any activity or service, so it's where crash
 * reporting is brought up (subject to the user's opt-out) to catch failures that
 * happen during early startup.
 */
class RayfishApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Telemetry.apply(this)
    }
}
