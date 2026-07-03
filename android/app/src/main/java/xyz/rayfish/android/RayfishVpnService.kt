package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking

/**
 * Foreground [VpnService] that captures the phone's packets and hands the tunnel
 * fd to the Rust core via [Node.up]. Starting/stopping is driven from
 * [MainActivity] after the system consent dialog ([VpnService.prepare]).
 */
class RayfishVpnService : VpnService() {

    @Volatile
    private var tunnel: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (tunnel != null) return
        startForegroundNotification()

        val builder = Builder()
            .setSession("Rayfish")
            .addAddress("100.64.0.2", 32)
            .addRoute("100.64.0.0", 10)
            .setMtu(1280)

        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null; tunnel not up")
            stopSelf()
            return
        }
        tunnel = pfd

        // Node.up drives the blocking-ish bring-up (endpoint bind, forward loop
        // spawn) so keep it off the main thread. detachFd() transfers ownership
        // of the tunnel fd to the Rust side, which closes it on Node.down; our
        // ParcelFileDescriptor no longer owns an fd, so tunnel?.close() on stop
        // is a harmless no-op kept only to clear the reference.
        //
        // ensureStarted() MUST run before up(): the node needs start() (which
        // builds the headless daemon and reconnects saved networks) or up()
        // returns NotStarted. The service is START_STICKY, so the system can
        // restart it with no Activity ever created and the UI's ensureStarted
        // never running; starting it here makes the service self-sufficient.
        thread(name = "rayfish-node-up") {
            try {
                runBlocking { NodeHolder.ensureStarted(applicationContext) }
                NodeHolder.get(applicationContext).up(pfd.detachFd())
                Log.i(TAG, "Node.up succeeded")
            } catch (t: Throwable) {
                Log.e(TAG, "Node bring-up failed", t)
            }
        }
    }

    private fun stopTunnel() {
        try {
            NodeHolder.get(applicationContext).down()
        } catch (t: Throwable) {
            Log.w(TAG, "Node.down failed (may not have been up)", t)
        }
        try {
            tunnel?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "closing tunnel fd failed", t)
        }
        tunnel = null
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Rayfish VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "Rayfish mesh tunnel status" }
            nm.createNotificationChannel(channel)
        }

        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Rayfish")
            .setContentText("Mesh tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    companion object {
        private const val TAG = "RayfishVpn"
        private const val CHANNEL_ID = "rayfish_vpn"
        private const val NOTIF_ID = 1
        const val ACTION_STOP = "xyz.rayfish.android.STOP"
    }
}
