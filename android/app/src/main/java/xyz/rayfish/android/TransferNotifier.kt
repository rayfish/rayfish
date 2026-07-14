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
    private const val CHANNEL_ID = "rayfish_transfers"
    // Offset well clear of the VPN (1) and SendService notification ids.
    private const val NOTIF_BASE = 5000
    private val terminal = java.util.Collections.synchronizedSet(HashSet<ULong>())

    /** Read the registry and reconcile notifications. Safe on any thread. */
    fun poll(context: Context) {
        val transfers = runCatching { NodeHolder.get(context).listTransfers() }.getOrNull() ?: return
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
    }

    private fun notifId(id: ULong): Int = NOTIF_BASE + (id.toInt() and 0xffff)

    private fun postProgress(context: Context, t: uniffi.ray_mobile.Transfer) {
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

    private fun ensureChannel(context: Context) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "File transfers",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "Progress and results for files sent and received over the mesh" }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
}
