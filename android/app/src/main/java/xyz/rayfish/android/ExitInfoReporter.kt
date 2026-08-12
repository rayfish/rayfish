package xyz.rayfish.android

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import io.sentry.Attachment
import io.sentry.Sentry
import io.sentry.SentryLevel
import io.sentry.android.core.SentryLogcatAdapter as Log

/**
 * Reports how the previous process died, using Android's own record of it.
 *
 * The motivating case: a background ANR arrived with an idle main thread and no
 * app frame anywhere, so there was nothing to attribute it to. That is normal
 * for a trace captured when the process is reaped rather than when it stalled.
 * Android keeps the missing piece in [ApplicationExitInfo.getDescription], which
 * names the component that timed out ("executing service .../.RayfishVpnService",
 * "Broadcast of Intent { ... }", "Input dispatching timed out"), and the raw
 * trace in [ApplicationExitInfo.getTraceInputStream]. Neither is surfaced by the
 * SDK's own ANR reporting, so an unattributable ANR stays unattributable.
 *
 * This also covers the exits that produce no report at all today: a low-memory
 * kill leaves no crash and no ANR, so a VPN app that is supposed to stay resident
 * simply vanishes from the mesh with nothing in the dashboard to say why.
 *
 * An ANR therefore lands twice: once from the SDK's AppExitInfo integration
 * (which parses the trace into thread frames) and once from here (which carries
 * the description and the raw trace). That duplication is deliberate. The two
 * records answer different questions, ANRs are rare enough that the noise is
 * negligible, and enriching the SDK's event instead would mean matching our
 * record to its event by timestamp inside beforeSend, which is fragile and
 * version-dependent for no real gain.
 *
 * Gated by the same crash-reporting opt-out as everything else: [Sentry.isEnabled]
 * is false when the user has turned it off, so nothing is read or sent.
 */
object ExitInfoReporter {
    private const val TAG = "RayfishExitInfo"

    // How many exit records to ask Android for. It keeps at most 16 per app, and
    // anything older than the last handful is stale news by the time we look.
    private const val MAX_RECORDS = 16

    // Cap on the attached trace. ANR traces dump every thread in the process and
    // ours runs a tokio runtime plus an iroh blob store, so they get large; past
    // this point the tail is not worth the upload on a metered connection.
    private const val MAX_TRACE_BYTES = 512 * 1024

    // Timestamp of the newest record already reported, so a record is sent once
    // and not again on every launch. Lives in NodeHolder's prefs file.
    private const val KEY_LAST_REPORTED = "last_exit_report_ts"

    /**
     * Report any exits not seen before. Does disk I/O (the prefs read and the
     * trace stream), so it must not run on the main thread: the caller is
     * responsible for that.
     */
    fun reportNewExits(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        if (!Sentry.isEnabled()) return

        val am = context.getSystemService(ActivityManager::class.java) ?: return
        val records = runCatching {
            am.getHistoricalProcessExitReasons(context.packageName, 0, MAX_RECORDS)
        }.getOrElse {
            Log.w(TAG, "could not read historical exit reasons", it)
            return
        }
        if (records.isEmpty()) return

        val prefs = NodeHolder.prefs(context)
        // getHistoricalProcessExitReasons returns newest first; the newest
        // timestamp becomes the new watermark whether or not we report it, so an
        // uninteresting exit does not get re-examined on every launch.
        val newest = records.first().timestamp

        if (!prefs.contains(KEY_LAST_REPORTED)) {
            // First launch on a build that has this reporter. Android still holds
            // up to 16 records from before it existed, and sending them now would
            // put a burst of months-old, unactionable exits in the dashboard from
            // every install at once, all of them predating the code they would be
            // read against. Set the watermark and report from here on.
            prefs.edit().putLong(KEY_LAST_REPORTED, newest).apply()
            Log.i(TAG, "exit reporting armed at $newest; ${records.size} pre-existing records skipped")
            return
        }

        val lastReported = prefs.getLong(KEY_LAST_REPORTED, 0L)
        for (record in records) {
            if (record.timestamp <= lastReported) break
            if (!isInteresting(record.reason)) continue
            runCatching { report(context, record) }
                .onFailure { Log.w(TAG, "could not report exit record", it) }
        }

        if (newest > lastReported) {
            prefs.edit().putLong(KEY_LAST_REPORTED, newest).apply()
        }
    }

    /**
     * Exits worth a report: the process died for a reason the user did not ask
     * for. Deliberately excludes the ordinary ones (the user swiping the app
     * away, our own exit, a package update), which are not faults and would bury
     * the ones that are.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    private fun isInteresting(reason: Int): Boolean = when (reason) {
        ApplicationExitInfo.REASON_ANR,
        ApplicationExitInfo.REASON_CRASH_NATIVE,
        ApplicationExitInfo.REASON_LOW_MEMORY,
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE,
        ApplicationExitInfo.REASON_SIGNALED,
        ApplicationExitInfo.REASON_PERMISSION_CHANGE,
        -> true
        // REASON_CRASH is the JVM crash the SDK already reports in full, with a
        // real stack trace. A second, poorer record of the same death helps
        // nobody.
        else -> false
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun report(context: Context, record: ApplicationExitInfo) {
        val reason = reasonName(record.reason)
        // The description carries the identifying detail, but its tail varies per
        // occurrence (a whole Intent dump, pids, timings), so grouping on the raw
        // string would give one issue per event. Everything before the first
        // brace is the stable part: "Broadcast of Intent" or the service name.
        val description = record.description ?: ""
        val grouping = description.substringBefore('{').trim().ifEmpty { "no description" }

        // Read before entering the scope: this touches the filesystem and can
        // fail, and there is nothing to be gained from doing it with a scope
        // held open.
        val trace = readTrace(record)

        Sentry.withScope { scope ->
            scope.level = SentryLevel.WARNING
            scope.setTag("install_id", NodeHolder.installId(context))
            scope.setTag("exit_reason", reason)
            scope.setFingerprint(listOf("app-exit", reason, grouping))
            scope.setContexts("app_exit", mapOf(
                "reason" to reason,
                "description" to description,
                "importance" to importanceName(record.importance),
                "pss_kb" to record.pss,
                "rss_kb" to record.rss,
                "timestamp" to record.timestamp,
            ))
            if (trace != null) {
                scope.addAttachment(Attachment(trace, "app-exit-trace.txt", "text/plain"))
            }
            Sentry.captureMessage("app exit: $reason ($grouping)")
        }
        Log.i(TAG, "reported previous app exit: $reason ($grouping), trace=${trace?.size ?: 0}B")
    }

    /**
     * The ANR / native trace, when there is one. This is the payload that makes
     * the report worth sending: for an ANR it is the thread dump taken at the
     * moment the system decided the app was unresponsive, not at reap time.
     *
     * Read by hand rather than with readNBytes, which needs API 33 while this app
     * ships to 24. Truncated rather than streamed whole, see [MAX_TRACE_BYTES].
     */
    @RequiresApi(Build.VERSION_CODES.R)
    private fun readTrace(record: ApplicationExitInfo): ByteArray? = runCatching {
        record.traceInputStream?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(16 * 1024)
            while (out.size() < MAX_TRACE_BYTES) {
                val read = input.read(chunk)
                if (read < 0) break
                out.write(chunk, 0, minOf(read, MAX_TRACE_BYTES - out.size()))
            }
            out.toByteArray()
        }
    }.getOrNull()?.takeIf { it.isNotEmpty() }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun reasonName(reason: Int): String = when (reason) {
        ApplicationExitInfo.REASON_ANR -> "anr"
        ApplicationExitInfo.REASON_CRASH -> "crash"
        ApplicationExitInfo.REASON_CRASH_NATIVE -> "crash_native"
        ApplicationExitInfo.REASON_LOW_MEMORY -> "low_memory"
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "excessive_resource_usage"
        ApplicationExitInfo.REASON_SIGNALED -> "signaled"
        ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "permission_change"
        ApplicationExitInfo.REASON_USER_REQUESTED -> "user_requested"
        ApplicationExitInfo.REASON_USER_STOPPED -> "user_stopped"
        ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "dependency_died"
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "initialization_failure"
        ApplicationExitInfo.REASON_EXIT_SELF -> "exit_self"
        ApplicationExitInfo.REASON_OTHER -> "other"
        else -> "unknown_$reason"
    }

    // Whether the process was foreground, cached, or already invisible when it
    // died. A low-memory kill of a cached process is routine; the same kill of a
    // process running our foreground service is a bug in how we hold it.
    private fun importanceName(importance: Int): String = when (importance) {
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND -> "foreground"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE -> "foreground_service"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE -> "visible"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_PERCEPTIBLE -> "perceptible"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE -> "service"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED -> "cached"
        else -> "unknown_$importance"
    }
}
