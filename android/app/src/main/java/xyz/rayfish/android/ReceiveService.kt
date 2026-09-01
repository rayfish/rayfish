package xyz.rayfish.android

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import io.sentry.android.core.SentryLogcatAdapter as Log
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import uniffi.ray_mobile.FileOffer

/**
 * Takes or declines one incoming file offer on behalf of a notification action, so
 * a file sent by another peer can be saved without opening the app.
 *
 * The mirror image of [SendService], and foreground for the same reason:
 * `acceptFileOffer` blocks for the whole download, which is far longer than a
 * BroadcastReceiver may live and long enough for a background process to be
 * killed mid-transfer. Starting a foreground service from the background is
 * otherwise blocked, but tapping a notification action puts the app on the
 * system's temporary allowlist, which is the exemption this relies on.
 *
 * Progress and the final result are [TransferNotifier]'s: the core registers a
 * transfer as soon as the accept starts, and the pollers report it from there.
 * This service's own notification only exists because a foreground service must
 * have one, and goes away as soon as the accept returns.
 */
class ReceiveService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        val id = intent?.getLongExtra(EXTRA_OFFER_ID, -1L) ?: -1L
        if (intent == null || id < 0) {
            // Nothing to do, but a service started with startForegroundService
            // must still go foreground before it is allowed to stop, or the
            // system kills the process with a ForegroundServiceDidNotStartInTime
            // ANR. Post, then stop -- but under the same lock and the same
            // in-flight check as a finishing worker, or this no-op command would
            // drop a running accept out of the foreground and stop the service
            // out from under it.
            synchronized(lifecycle) {
                startForegroundNotification(getString(R.string.app_name), getString(R.string.notif_working))
                if (inFlight.get() == 0) {
                    stopForegroundCompat()
                    stopSelf(startId)
                } else {
                    lastStartId = startId
                }
            }
            return START_NOT_STICKY
        }
        val offerId = id.toULong()
        val filename = intent.getStringExtra(EXTRA_FILENAME) ?: getString(R.string.fallback_file)
        val peer = intent.getStringExtra(EXTRA_PEER) ?: getString(R.string.fallback_peer)
        val size = intent.getLongExtra(EXTRA_SIZE, 0L).toULong()
        val mime = intent.getStringExtra(EXTRA_MIME) ?: ""

        // Take the offer notification down and stop the pollers reporting it
        // before any blocking work starts: the core only drops the pending entry
        // once acceptFileOffer actually runs on the worker thread below, so a
        // poll landing in between would otherwise post the offer straight back
        // over the action the user just took.
        OfferNotifier.markActedOn(applicationContext, offerId)

        val accepting = action == ACTION_ACCEPT
        // Counted *before* going foreground, and under the lock a finishing
        // worker also takes. A worker whose `finally` lands between the two
        // would otherwise see the count reach zero and leave the foreground
        // again, dropping this command's transfer to a background service.
        synchronized(lifecycle) {
            inFlight.incrementAndGet()
            lastStartId = startId
            startForegroundNotification(
                if (accepting) getString(R.string.notif_saving_file, filename) else getString(R.string.app_name),
                if (accepting) getString(R.string.notif_from_peer, peer) else getString(R.string.notif_declining_file, filename),
            )
        }

        // Blocking FFI work off the main thread. The cleanup is not best-effort:
        // anything thrown here used to be able to kill the thread before it left
        // the foreground, stranding an ongoing notification with no service
        // behind it to ever clear it.
        thread(name = "rayfish-receive-$startId") {
            try {
                if (accepting) accept(offerId, filename, peer, size, mime) else reject(offerId, filename)
            } catch (t: Throwable) {
                Log.e(TAG, "receive action $action for $filename failed", t)
                // A failed accept still consumed the offer core-side, but a failed
                // reject did not: let the next poll put the notification back
                // rather than suppressing an offer that is still sitting there
                // with no way left to answer it.
                OfferNotifier.clearActedOn(offerId)
            } finally {
                // Only the last one out tears anything down. startForeground and
                // stopForeground are service-wide, not per start command, so a
                // short reject finishing while a long accept is still downloading
                // would otherwise drop that download to a background service and
                // strand its notification.
                //
                // stopSelf needs the same guard, which is the opposite of what it
                // looks like: it stops the service when the id *is* the most
                // recent start, so in exactly that reject-over-accept case the
                // reject's own `stopSelf(2)` destroyed the service while the
                // accept was still downloading. It also has to name the newest
                // start rather than ours, or the accept finishing second would
                // call `stopSelf(1)` while 2 is the most recent, which is a no-op
                // and leaves the service up for good.
                synchronized(lifecycle) {
                    if (inFlight.decrementAndGet() == 0) {
                        stopForegroundCompat()
                        stopSelf(lastStartId)
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    /** Fetch the file and move it into Downloads. The same two steps as the
     * own-device auto-accept path, and the same [DownloadsOutcome] bookkeeping:
     * the core reports the transfer DONE from inside acceptFileOffer, before a
     * single byte has been copied to Downloads, so a poller must see "pending"
     * from the first moment DONE can appear or it will post a result that claims
     * the wrong location. */
    private fun accept(id: ULong, filename: String, peer: String, size: ULong, mime: String) {
        val ctx = applicationContext
        val saveDir = ctx.getExternalFilesDir(null)?.absolutePath ?: ctx.filesDir.absolutePath
        val key = TransferKey(peer, filename, size)
        DownloadsOutcome.markPending(key)
        try {
            NodeHolder.get(ctx).acceptFileOffer(id, saveDir)
        } catch (t: Throwable) {
            // The accept failed, so no Downloads outcome is ever coming for this
            // key: stop treating it as pending rather than making the result
            // notification wait out the timeout for a failure already known.
            DownloadsOutcome.clearPending(key)
            throw t
        }
        // Re-stamp now that the download is done and the copy is about to start.
        // The first mark only had to cover the wait for DONE to appear, and the
        // download itself can run far longer than the pending timeout.
        DownloadsOutcome.markPending(key)
        val reached = moveToDownloads(ctx, File(saveDir, filename), filename, mime)
        DownloadsOutcome.record(key, reached)
        Log.i(TAG, "saved $filename from $peer (downloads=$reached)")
    }

    private fun reject(id: ULong, filename: String) {
        NodeHolder.get(applicationContext).rejectFileOffer(id)
        Log.i(TAG, "rejected offer for $filename")
    }

    private fun startForegroundNotification(title: String, text: String) {
        TransferNotifier.ensureChannel(this)
        val notification = Notification.Builder(this, TransferNotifier.CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ONGOING, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ONGOING, notification)
        }
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        private const val TAG = "RayfishReceive"

        // Clear of the VPN (1) and SendService (2) foreground ids. Shared by every
        // start command: two concurrent accepts are one service with one
        // foreground notification, and the last stopSelf(startId) takes it down.
        private const val NOTIF_ONGOING = 3

        /** Serializes going foreground against leaving it. Both the count and
         * the foreground state are service-wide, so incrementing and posting must
         * not interleave with a worker decrementing and tearing down. */
        private val lifecycle = Any()

        /** Start commands whose worker thread has not finished yet. */
        private val inFlight = AtomicInteger(0)

        /** The most recent start command, which is the only id `stopSelf` acts
         * on. Guarded by [lifecycle]. */
        private var lastStartId = 0

        const val ACTION_ACCEPT = "xyz.rayfish.android.ACCEPT_OFFER"
        const val ACTION_REJECT = "xyz.rayfish.android.REJECT_OFFER"

        private const val EXTRA_OFFER_ID = "offer_id"
        private const val EXTRA_FILENAME = "filename"
        private const val EXTRA_PEER = "peer"
        private const val EXTRA_SIZE = "size"
        private const val EXTRA_MIME = "mime"

        /** The offer is carried in the intent rather than looked up by id at
         * action time: the pending entry is gone the moment the accept starts, so
         * a later re-read would find nothing to name the file or the peer with,
         * and both are needed for the Downloads bookkeeping. */
        fun intent(context: Context, action: String, f: FileOffer): Intent =
            Intent(context, ReceiveService::class.java).apply {
                this.action = action
                putExtra(EXTRA_OFFER_ID, f.id.toLong())
                putExtra(EXTRA_FILENAME, f.filename)
                putExtra(EXTRA_PEER, f.from)
                putExtra(EXTRA_SIZE, f.size.toLong())
                putExtra(EXTRA_MIME, f.mimeType)
            }
    }
}
