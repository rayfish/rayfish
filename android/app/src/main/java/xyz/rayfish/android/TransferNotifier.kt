package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import io.sentry.android.core.SentryLogcatAdapter as Log
import uniffi.ray_mobile.TransferState

/**
 * Turns the core's transfer registry into notifications: a progress bar while bytes
 * move, then a done or failed result.
 *
 * A send sits in [TransferState.OFFERED] until the recipient accepts, which can be
 * a while (or never) for a manual accept. Only when they start pulling the blob out
 * of our store do real byte counts arrive, so OFFERED shows as indeterminate
 * "waiting for <peer>", and DONE means they actually have the file.
 *
 * Whichever service is alive drives this: [SendService] during an active send, the
 * [RayfishVpnService] poller in the background. Both call [poll]; notification ids
 * are derived from the transfer id, so a double-drive updates rather than
 * duplicates, and a terminal state is posted exactly once.
 */
object TransferNotifier {
    internal const val CHANNEL_ID = "rayfish_transfers"
    // Offset well clear of the VPN (1) and SendService notification ids.
    private const val NOTIF_BASE = 5000
    private val terminal = java.util.Collections.synchronizedSet(HashSet<ULong>())
    // Transfer ids we have posted an ongoing progress notification for in this
    // process. Used to cancel the notification once the transfer leaves the
    // registry (Critical 1a) without ever having reached a terminal state we
    // observed ourselves.
    private val postedProgress = java.util.Collections.synchronizedSet(HashSet<ULong>())
    @Volatile private var channelEnsured = false
    private var cancelledStaleOnStart = false

    /**
     * Read the registry and reconcile notifications. Safe on any thread.
     *
     * The whole body runs under a single lock: [SendService] and the VPN
     * poller both call this concurrently, and without serializing the read
     * (listTransfers) plus the write (notify) as one step, one driver can
     * post a "Sent" result and the other, working off a snapshot taken a
     * moment earlier, can then post a progress bar over it that nothing
     * ever clears (Critical 2).
     */
    fun poll(context: Context) {
        synchronized(this) {
            // The core's transfer registry starts empty on every process start, so
            // any ongoing notification still showing at this point is necessarily
            // left over from a previous process and can never be resolved by this
            // one (Critical 1b). Clear it once, before posting anything ourselves.
            if (!cancelledStaleOnStart) {
                cancelledStaleOnStart = true
                cancelStaleOngoingNotifications(context)
            }

            val transfers = runCatching { NodeHolder.get(context).listTransfers() }.getOrNull() ?: return
            val liveIds = transfers.mapTo(HashSet()) { it.id }
            for (t in transfers) {
                when (t.state) {
                    TransferState.OFFERED, TransferState.TRANSFERRING -> postProgress(context, t)
                    TransferState.DONE, TransferState.FAILED -> {
                        // Terminal entries stay listable for 60s, so guard against
                        // re-posting the same result on every poll.
                        if (terminal.add(t.id)) postResult(context, t)
                    }
                }
            }
            pruneVanished(context, liveIds)
        }
    }

    /** Cancel any ongoing notification left over from a previous process, on our
     * channel and in our own id range. Only called once, before this process has
     * posted anything of its own.
     *
     * This must never be able to touch SendService's live foreground notification:
     * on a cold share the foreground notification is posted (id 2, same channel,
     * ongoing) before the send thread's first poll, so a sweep that only checked
     * channel + FLAG_ONGOING_EVENT would match it too. Two guards keep it out:
     * FLAG_FOREGROUND_SERVICE (a foreground notification always carries it) and
     * the id range (our own notifications are all >= NOTIF_BASE; SendService's
     * ids are below it). */
    private fun cancelStaleOngoingNotifications(context: Context) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) return
        val nm = context.getSystemService(NotificationManager::class.java)
        runCatching {
            for (sbn in nm.activeNotifications) {
                val n = sbn.notification
                if (sbn.id < NOTIF_BASE) continue
                if ((n.flags and Notification.FLAG_FOREGROUND_SERVICE) != 0) continue
                if (n.channelId == CHANNEL_ID && (n.flags and Notification.FLAG_ONGOING_EVENT) != 0) {
                    nm.cancel(sbn.id)
                }
            }
        }
    }

    /** Anything we posted a progress bar for that has since left the registry
     * without ever reaching a terminal state we observed (the process died and
     * restarted mid-transfer, or the entry simply vanished) is stale: cancel it
     * so it cannot outlive the transfer it describes.
     *
     * A result notification's id is removed from [postedProgress] by [postResult]
     * itself, precisely so this loop can never reach it: once a result is posted,
     * that notification is done and permanent (until the user dismisses it or
     * taps it), it must not be cancelled just because the terminal entry aged out
     * of the registry 60s later. Also prunes [terminal] so it does not grow
     * forever (minor 6). */
    private fun pruneVanished(context: Context, liveIds: Set<ULong>) {
        val nm = context.getSystemService(NotificationManager::class.java)
        val vanished = postedProgress.filter { it !in liveIds }
        for (id in vanished) {
            nm.cancel(notifId(id))
            postedProgress.remove(id)
        }
        terminal.removeAll { it !in liveIds }
    }

    private fun notifId(id: ULong): Int = NOTIF_BASE + (id.toInt() and 0x7fffffff)

    private fun postProgress(context: Context, t: uniffi.ray_mobile.Transfer) {
        // A terminal result for this id has already been posted (or is about to
        // be, by whichever driver won the race): never draw a progress bar back
        // over it (Critical 2).
        if (t.id in terminal) return
        postedProgress.add(t.id)
        ensureChannel(context)
        val waiting = t.state == TransferState.OFFERED
        val title = if (t.outgoing) "Sending ${t.filename}" else "Receiving ${t.filename}"
        val text = when {
            waiting -> "Waiting for ${t.peer} to accept"
            t.outgoing -> "To ${t.peer}"
            else -> "From ${t.peer}"
        }
        val builder = Notification.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(
                if (t.outgoing) android.R.drawable.stat_sys_upload
                else android.R.drawable.stat_sys_download,
            )
            .setOngoing(true)
            .setOnlyAlertOnce(true)
        // Indeterminate while we are only waiting on the peer; a real bar once bytes
        // move. size can be 0 for an empty file, so guard the division.
        if (waiting || t.size == 0uL) {
            builder.setProgress(0, 0, true)
        } else {
            val pct = ((t.transferred.toDouble() / t.size.toDouble()) * 100).toInt().coerceIn(0, 100)
            builder.setProgress(100, pct, false)
        }
        context.getSystemService(NotificationManager::class.java)
            .notify(notifId(t.id), builder.build())
    }

    private fun postResult(context: Context, t: uniffi.ray_mobile.Transfer) {
        // This id no longer names an ongoing notification: it is about to become a
        // result notification instead. Drop it from postedProgress so pruneVanished
        // can never mistake the result for a vanished progress bar and cancel it out
        // from under the user 60s later when the terminal entry ages out of the
        // registry (Critical 1).
        postedProgress.remove(t.id)
        ensureChannel(context)
        val ok = t.state == TransferState.DONE
        val title = when {
            ok && t.outgoing -> "Sent ${t.filename}"
            ok -> "Saved ${t.filename}"
            t.outgoing -> "Could not send ${t.filename}"
            else -> "Could not receive ${t.filename}"
        }
        val text = when {
            ok && t.outgoing -> "${t.peer} has it"
            ok -> "Saved to Downloads"
            else -> "Transfer with ${t.peer} failed"
        }
        // Tapping a received file opens Downloads; a sent one opens the app.
        val intent = if (ok && !t.outgoing) {
            Intent(android.app.DownloadManager.ACTION_VIEW_DOWNLOADS)
        } else {
            Intent(context, MainActivity::class.java)
        }
        val tap = PendingIntent.getActivity(
            context, notifId(t.id), intent, PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(
                if (ok) android.R.drawable.stat_sys_download_done
                else android.R.drawable.stat_notify_error,
            )
            .setAutoCancel(true)
            .setContentIntent(tap)
            .build()
        context.getSystemService(NotificationManager::class.java)
            .notify(notifId(t.id), notification)
        Log.i("RayfishTransfers", "transfer ${t.id} ${t.state} (${t.filename})")
    }

    /** Called on every post, but only does binder work once per process: creating an
     * already-existing channel also silently overwrites its name/description, so a
     * second definition anywhere would make the label in system Settings flip-flop
     * depending on which ran last (minor 7). This is the one definition; [SendService]
     * reuses it instead of declaring its own. */
    internal fun ensureChannel(context: Context) {
        if (channelEnsured) return
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) {
            channelEnsured = true
            return
        }
        val channel = NotificationChannel(
            CHANNEL_ID,
            "File transfers",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "Progress and results for files sent and received over the mesh" }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        // Set only after the channel actually exists: another thread reading
        // channelEnsured == true before createNotificationChannel returns could
        // notify() on a channel the platform doesn't know about yet and have the
        // notification silently dropped.
        channelEnsured = true
    }
}
