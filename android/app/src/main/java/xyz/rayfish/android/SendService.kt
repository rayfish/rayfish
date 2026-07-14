package xyz.rayfish.android

import android.app.Notification
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
import uniffi.ray_mobile.TransferState

/**
 * Foreground service that delivers shared files over the mesh in the background, so
 * the user is never blocked waiting on a send. Started by [ShareActivity] once a
 * recipient is picked; the activity finishes immediately.
 *
 * [uniffi.ray_mobile.Node.sendFile] offers the file (metadata + blob hash) to the
 * peer and returns once the offer is delivered, not once the peer has it: the
 * recipient decides asynchronously (auto-accept for its own paired devices,
 * otherwise a manual Save) and pulls the bytes from our blob store when it
 * accepts, which can be minutes later or never. This service stays foreground
 * and reports real per-transfer progress via [TransferNotifier] until every
 * offer reaches a terminal state or [WAIT_TIMEOUT_MS] passes; after that, the
 * only thing left that can report a result is [RayfishVpnService]'s background
 * poller, and that only runs while some instance of that service is actually
 * alive (the VPN on, or standby keeping the control plane running). A plain
 * `NodeHolder.ensureStarted` with no `RayfishVpnService` running (e.g.
 * `ShareActivity` sharing with the VPN off and go-fully-offline enabled) starts no
 * poller at all: the transfer still completes in the core, but nobody is
 * listening, so the result notification never arrives. [TransferNotifier]'s
 * "waiting" notification says this plainly rather than implying a result
 * notification is always coming.
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
            // sendFile does not return a transfer id, so we cannot name this batch's
            // transfers directly. Instead bound them from both sides: take the max
            // id already in the registry before offering anything, then again right
            // after the offer loop finishes. This batch's transfers are exactly the
            // ones present in the "after" snapshot with an id greater than the "before"
            // max: newly created since we started, and already known to the registry
            // by the time we start waiting.
            //
            // That two-sided bound is not sufficient by itself with two concurrent
            // shares: it only excludes a batch that starts after this one's "after"
            // snapshot. It does nothing about a batch whose offers land while this
            // one is still in the middle of its own offer loop: each sendFile reads
            // the whole file, hashes it, adds it to the blob store, and then dials
            // the peer over QUIC with no client-side timeout, so that window can be
            // long, not just seconds. Those ids are newly created and greater than
            // maxIdBeforeBatch, so the after-snapshot would wrongly claim them as
            // this batch's own. If that other batch's peer never accepts, this one
            // would burn the full wait timeout for a file it delivered in seconds.
            // So the region from taking the "before" max through the "after"
            // snapshot is serialized behind batchLock: two batches' offers can never
            // interleave, only one runs that region at a time.
            //
            // Staging (a full byte copy through ContentResolver) allocates no
            // transfer ids, so it happens before the lock is taken: only the id
            // snapshots and the sendFile loop itself, which must stay atomic with
            // respect to id allocation, run inside it. The lock is released before
            // the wait loop below, so concurrent batches still wait for their own
            // peers in parallel; only the offering is serialized, not the (much
            // longer) waiting. A batch can still be blocked by another batch's
            // sendFile dialing an offline peer, but that is bounded by the QUIC
            // dial itself rather than by staging plus dial.
            var offered = 0
            var failed = 0
            val staged = uris.mapNotNull { uri -> stageUriForSend(applicationContext, uri) }
            failed += uris.size - staged.size

            val maxIdBeforeBatch: Long?
            val batchIds: Set<ULong>?
            synchronized(batchLock) {
                maxIdBeforeBatch = runCatching {
                    NodeHolder.get(applicationContext).listTransfers().maxOfOrNull { it.id.toLong() } ?: -1L
                }.getOrNull()

                for (file in staged) {
                    try {
                        NodeHolder.get(applicationContext).sendFile(file.absolutePath, peerId)
                        offered++
                    } catch (t: Throwable) {
                        failed++
                        Log.w(TAG, "send failed for ${file.name}", t)
                    } finally {
                        // Bytes are in the blob store now; the staging copy is no
                        // longer needed. Remove the file and its per-item dir.
                        runCatching { file.parentFile?.deleteRecursively() ?: file.delete() }
                    }
                }

                batchIds = if (maxIdBeforeBatch == null) {
                    null
                } else {
                    runCatching {
                        NodeHolder.get(applicationContext).listTransfers()
                            .mapNotNullTo(HashSet()) { it.id.takeIf { id -> id.toLong() > maxIdBeforeBatch } }
                    }.getOrNull()
                }
            }

            // The offers are delivered, but the bytes have not moved: the peer pulls
            // them when it accepts. Stay foreground and let TransferNotifier report
            // real progress until every transfer reaches a terminal state, so the
            // user sees a progress bar and then a genuine "sent".
            //
            // A manual accept on the other end can take arbitrarily long, and an
            // indefinite foreground service is not acceptable, so give up the
            // service after WAIT_TIMEOUT_MS. The transfer is not cancelled by that:
            // it keeps running in the core, and the background poller in
            // RayfishVpnService posts the result whenever it lands, provided the node
            // is still alive (VPN on, or in standby).
            //
            // If either snapshot failed, we cannot bound this batch at all: waiting
            // on an unscoped count would silently reinstate the same bug the scoping
            // was meant to kill, so don't wait rather than wait on everything.
            if (offered > 0 && batchIds != null) {
                val deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MS
                while (System.currentTimeMillis() < deadline) {
                    TransferNotifier.poll(applicationContext)
                    val pending = runCatching {
                        NodeHolder.get(applicationContext).listTransfers()
                            .count {
                                it.outgoing && it.id in batchIds &&
                                    (it.state == TransferState.OFFERED || it.state == TransferState.TRANSFERRING)
                            }
                    }.getOrDefault(0)
                    if (pending == 0) break
                    Thread.sleep(POLL_INTERVAL_MS)
                }
                TransferNotifier.poll(applicationContext)
            } else if (offered > 0) {
                TransferNotifier.poll(applicationContext)
            }

            if (failed > 0) notifyFailure(peerName, failed)
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
        TransferNotifier.ensureChannel(this)
        val label = if (count == 1) "1 item" else "$count items"
        val notification: Notification = Notification.Builder(this, TransferNotifier.CHANNEL_ID)
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

    /** Staging or offer failures only. Successful sends are reported per transfer by
     * [TransferNotifier] once the peer has actually pulled the bytes. */
    private fun notifyFailure(peerName: String, failed: Int) {
        TransferNotifier.ensureChannel(this)
        val text = if (failed == 1) "Could not send 1 item to $peerName"
        else "Could not send $failed items to $peerName"
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, TransferNotifier.CHANNEL_ID)
            .setContentTitle("Rayfish")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        // A distinct id per call: two batches with the same failure count (e.g. one
        // item each, to different peers) must not overwrite each other's notification.
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_RESULT_BASE + failureNotifSeq.incrementAndGet(), notification)
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
        private const val NOTIF_ONGOING = 2
        private const val NOTIF_RESULT_BASE = 100
        // How long the foreground service waits for recipients to pull the bytes
        // before handing off to the background poller. A manual accept can take far
        // longer than this; the transfer survives, only the foreground service ends.
        private const val WAIT_TIMEOUT_MS = 3 * 60 * 1000L
        private const val POLL_INTERVAL_MS = 1000L
        // Distinguishes failure notifications from concurrent batches that would
        // otherwise share the same NOTIF_RESULT_BASE + failed-count id.
        private val failureNotifSeq = java.util.concurrent.atomic.AtomicInteger(0)
        // Serializes the before-snapshot/offer-loop/after-snapshot region of
        // concurrent send batches so their offers can never interleave. Not held
        // across the wait loop: concurrent batches still wait on their own peers
        // in parallel, only the offering is serialized.
        private val batchLock = Any()
        const val EXTRA_PEER_ID = "xyz.rayfish.android.PEER_ID"
        const val EXTRA_PEER_NAME = "xyz.rayfish.android.PEER_NAME"
        const val EXTRA_URIS = "xyz.rayfish.android.URIS"
    }
}
