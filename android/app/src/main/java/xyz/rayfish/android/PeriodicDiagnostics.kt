package xyz.rayfish.android

import android.content.Context
import io.sentry.android.core.SentryLogcatAdapter as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Unattended diagnostics on a timer, for the failures nobody is holding the
 * phone to see.
 *
 * The problem it solves: the interesting failures here are the ones that cost
 * battery or connectivity overnight, and by morning the evidence is a percentage
 * in a system screen with no log behind it. A user-initiated "Send diagnostics"
 * only ever captures the moment someone happened to look, and the core's log ring
 * is bounded, so hours of a repeating fault evict themselves before anyone taps
 * anything.
 *
 * Opt-in, off by default ([NodeHolder.isPeriodicDiagnosticsEnabled]), and gated
 * behind crash reporting since it reports through the same Sentry client.
 *
 * Lives with [RayfishVpnService], which is alive exactly while the node is: with
 * a tunnel, or in standby with only the control plane up. There is deliberately
 * no scheduling when the node is fully offline. A report from a stopped node has
 * nothing to say, and the alternative (WorkManager, an alarm) would wake a
 * process the user has turned off in order to say so.
 */
object PeriodicDiagnostics {
    private const val TAG = "RayfishPeriodicDiag"

    /** How much wall clock one report covers. */
    private const val INTERVAL_MS = 8 * 60 * 60 * 1000L

    /**
     * How often the loop wakes to re-check. Well under [INTERVAL_MS] so that a
     * clock jump, a long doze, or an enable partway through a window is noticed
     * within the hour instead of at the next full interval.
     */
    private const val TICK_MS = 15 * 60 * 1000L

    /**
     * Network callbacks in a window past which the window is worth a report on
     * its own, with no warning or error needed to justify it.
     *
     * 500 in eight hours is roughly one a minute sustained. A phone that changes
     * network a dozen times a day does not come close; a phone whose radio is
     * republishing signal strength into an endpoint rebind blows through it in an
     * hour. The number only has to separate those two, and it is not load-bearing
     * beyond that: a window under it still reports when [rebinds] or the log
     * counters say so, and still carries its counts forward.
     */
    private const val CALLBACK_THRESHOLD = 500L

    /**
     * Rebinds actually dispatched past which a window is worth reporting. Lower
     * than [CALLBACK_THRESHOLD] because each one is a full endpoint rebind and
     * path re-probe, not a callback that the debounce may yet swallow: 120 in
     * eight hours is one every four minutes, which is already a radio that never
     * settles.
     */
    private const val REBIND_THRESHOLD = 120L

    private const val KEY_LAST_SEND_MS = "periodic_diag_last_send_ms"
    private const val KEY_LAST_WARN = "periodic_diag_last_warn"
    private const val KEY_LAST_ERROR = "periodic_diag_last_error"

    /**
     * Counts from windows that were not worth reporting, waiting to be added to
     * one that is. Process-local on purpose: the counters they came from are too,
     * so persisting this would claim a continuity across restarts that the source
     * does not have.
     */
    @Volatile
    private var carried: NetworkChurn? = null

    /**
     * One scope for the object, not one per [start]. A service that is destroyed
     * and recreated cancels the old job and launches a new one into the same
     * scope, rather than stranding a [SupervisorJob] per service instance.
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Start the loop. Returns the [Job] so the caller can cancel it; safe to call
     * with the feature turned off, since the pref is read per tick rather than
     * once here (the user can flip it while the service runs).
     */
    fun start(context: Context): Job {
        val app = context.applicationContext
        return scope.launch {
            // A fresh install (or one that has never sent) starts its first window
            // now rather than at the epoch, which would otherwise read as eight
            // hours overdue and fire a report about nothing on the first tick.
            if (lastSendMs(app) == 0L) recordSend(app, warn = null, error = null)
            while (isActive) {
                delay(TICK_MS)
                runCatching { tick(app) }
                    .onFailure { Log.w(TAG, "periodic diagnostics tick failed", it) }
            }
        }
    }

    /**
     * One wake-up. Drains the network counters whether or not it reports, so the
     * window boundary stays tied to the clock; a window that does not report
     * carries its counts into [carried] instead of losing them.
     */
    private fun tick(context: Context) {
        val elapsed = System.currentTimeMillis() - lastSendMs(context)
        // Negative when the wall clock went backwards (a system time correction,
        // which phones do). Treat that as a finished window rather than waiting
        // out an interval that now ends in the past.
        val windowClosed = elapsed !in 0 until INTERVAL_MS

        if (!NodeHolder.isPeriodicDiagnosticsEnabled(context)) {
            // Drop the counters rather than let them grow all the way to the next
            // enable, and keep the clock moving so turning the feature on does not
            // immediately fire a report covering a window nobody was counting.
            // The disk write waits for a window boundary: an install that leaves
            // this off forever should not be writing prefs every tick to say so.
            NodeHolder.takeNetworkChurn()
            carried = null
            if (windowClosed) recordSend(context, warn = null, error = null)
            return
        }
        if (!windowClosed) return

        val churn = (carried ?: NetworkChurn(emptyMap(), 0, 0)) + NodeHolder.takeNetworkChurn()
        val health = runCatching { NodeHolder.get(context).healthSnapshot() }.getOrNull()
        if (health == null) {
            // No node behind the FFI, so nothing to describe. Keep the counts:
            // they were real, and the next window can report them.
            carried = churn
            recordSend(context, warn = null, error = null)
            return
        }

        val warn = health.warnCount.toLong()
        val error = health.errorCount.toLong()
        // The core's counters run from process start, so they reset under us when
        // the process is restarted. A count lower than the last one recorded means
        // that happened, and the whole of the new count is news.
        val warnDelta = delta(warn, prev = context.prefs().getLong(KEY_LAST_WARN, 0))
        val errorDelta = delta(error, prev = context.prefs().getLong(KEY_LAST_ERROR, 0))

        val worthSending = warnDelta > 0 ||
            errorDelta > 0 ||
            churn.callbacks >= CALLBACK_THRESHOLD ||
            churn.rebinds >= REBIND_THRESHOLD
        if (!worthSending) {
            Log.i(TAG, "quiet window (${churn.callbacks} callbacks, ${churn.rebinds} rebinds); not sending")
            carried = if (churn.isQuiet()) null else churn
            recordSend(context, warn, error)
            return
        }

        val id = Telemetry.sendPeriodicDiagnostics(context, churn)
        if (id == null) {
            // Sentry refused or is not initialized. Keep the counts for the next
            // window rather than reporting them as having been sent.
            carried = churn
            Log.w(TAG, "periodic diagnostics send was refused")
            return
        }
        carried = null
        recordSend(context, warn, error)
        Log.i(
            TAG,
            "sent periodic diagnostics $id " +
                "(warn +$warnDelta, error +$errorDelta, " +
                "${churn.callbacks} callbacks, ${churn.rebinds} rebinds)",
        )
    }

    /** Growth since [prev], or all of [current] when the counter restarted under us. */
    private fun delta(current: Long, prev: Long): Long =
        if (current < prev) current else current - prev

    private fun Context.prefs() = NodeHolder.prefs(this)

    private fun lastSendMs(context: Context): Long =
        context.prefs().getLong(KEY_LAST_SEND_MS, 0)

    /**
     * Close the current window. [warn] and [error] are null when there was no
     * health snapshot to read them from, in which case the previously recorded
     * values stand: overwriting them with zero would make the next real snapshot
     * look like a burst of new warnings.
     */
    private fun recordSend(context: Context, warn: Long?, error: Long?) {
        context.prefs().edit().apply {
            putLong(KEY_LAST_SEND_MS, System.currentTimeMillis())
            if (warn != null) putLong(KEY_LAST_WARN, warn)
            if (error != null) putLong(KEY_LAST_ERROR, error)
        }.apply()
    }
}
