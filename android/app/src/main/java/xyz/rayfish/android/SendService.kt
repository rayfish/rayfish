package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import io.sentry.android.core.SentryLogcatAdapter as Log
import kotlin.concurrent.thread

/**
 * Foreground service that delivers shared files over the mesh in the background, so
 * the user is never blocked waiting on a send. Started by [ShareActivity] once a
 * recipient is picked; the activity finishes immediately.
 *
 * Sending is fire-and-forget by design: [uniffi.ray_mobile.Node.sendFile] offers the
 * file (metadata + blob hash) to the peer and returns once the offer is delivered —
 * it does not wait for the peer to download. The recipient decides asynchronously
 * (auto-accept for its own paired devices, otherwise a manual Save) and pulls the
 * bytes from our blob store when it accepts. So "Sent" here means "offered"; the
 * node stays online (via the VPN service, or the control plane brought up by
 * ensureStarted) to serve the bytes on demand.
 *
 * Each shared URI is staged to the app cache (the grant rides in on the start
 * intent's ClipData + FLAG_GRANT_READ_URI_PERMISSION), sent, then deleted.
 */
class SendService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val peerId = intent.getStringExtra(EXTRA_PEER_ID)
        val peerName = intent.getStringExtra(EXTRA_PEER_NAME) ?: "peer"
        val uris = collectUris(intent)
        if (peerId.isNullOrBlank() || uris.isEmpty()) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        startForegroundNotification(uris.size, peerName)

        // Blocking work (stage + FFI send) off the main thread. sendFile is a
        // synchronous FFI call. One thread per start command; stop this startId
        // when its batch finishes so concurrent shares each clean up independently.
        thread(name = "rayfish-send-$startId") {
            var sent = 0
            var failed = 0
            for (uri in uris) {
                val staged = stageUriForSend(applicationContext, uri)
                if (staged == null) {
                    failed++
                    continue
                }
                try {
                    NodeHolder.get(applicationContext).sendFile(staged.absolutePath, peerId)
                    sent++
                } catch (t: Throwable) {
                    failed++
                    Log.w(TAG, "send failed for ${staged.name}", t)
                } finally {
                    // Bytes are in the blob store now; the staging copy is no longer
                    // needed. Remove the file and its per-item dir.
                    runCatching { staged.parentFile?.deleteRecursively() ?: staged.delete() }
                }
            }
            notifyResult(peerName, sent, failed)
            stopForegroundCompat()
            stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    /** Prefer the ClipData URIs (the set the read grant was issued for); fall back
     * to the parcelable extra for robustness. */
    private fun collectUris(intent: Intent): List<Uri> {
        val clip = intent.clipData
        if (clip != null && clip.itemCount > 0) {
            return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
        }
        @Suppress("DEPRECATION")
        val extra: ArrayList<Uri>? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(EXTRA_URIS, Uri::class.java)
            } else {
                intent.getParcelableArrayListExtra(EXTRA_URIS)
            }
        return extra ?: emptyList()
    }

    private fun startForegroundNotification(count: Int, peerName: String) {
        ensureChannel()
        val label = if (count == 1) "1 item" else "$count items"
        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Sending to $peerName")
            .setContentText("$label over Rayfish")
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ONGOING, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ONGOING, notification)
        }
    }

    private fun notifyResult(peerName: String, sent: Int, failed: Int) {
        ensureChannel()
        val text = when {
            failed == 0 && sent == 1 -> "Sent 1 item to $peerName"
            failed == 0 -> "Sent $sent items to $peerName"
            sent == 0 -> "Failed to send to $peerName"
            else -> "Sent $sent to $peerName, $failed failed"
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Rayfish")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        // A fresh id per result so a completion isn't overwritten by the next send.
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_RESULT_BASE + (sent + failed), notification)
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID, "Rayfish file transfers", NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "Progress of files you share over Rayfish" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    companion object {
        private const val TAG = "RayfishSend"
        private const val CHANNEL_ID = "rayfish_transfers"
        private const val NOTIF_ONGOING = 2
        private const val NOTIF_RESULT_BASE = 100
        const val EXTRA_PEER_ID = "xyz.rayfish.android.PEER_ID"
        const val EXTRA_PEER_NAME = "xyz.rayfish.android.PEER_NAME"
        const val EXTRA_URIS = "xyz.rayfish.android.URIS"
    }
}
