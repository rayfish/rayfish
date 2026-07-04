package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
// Drop-in for android.util.Log: still prints to logcat (debug and release) and
// additionally records each line as a Sentry breadcrumb (context for a later
// crash) plus a structured log when Sentry logs are enabled (see Telemetry).
// Aliased to Log so the call sites below read unchanged. The Sentry side no-ops
// when the user has crash reporting opted out (Sentry stays uninitialized).
import io.sentry.android.core.SentryLogcatAdapter as Log
import java.net.Inet4Address
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
                // stopTunnel now blocks on a graceful endpoint close (so peers
                // see us drop cleanly and re-enable rebuilds without a stale
                // session). Run it off the main thread to avoid an ANR, then
                // stop the service.
                thread(name = "rayfish-node-stop") {
                    stopTunnel()
                    stopSelf()
                }
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (tunnel != null) return
        startForegroundNotification()

        // Bring the control plane up before building the tunnel so status() can
        // report our real mesh IP. ensureStarted is idempotent.
        val meshIp = try {
            runBlocking {
                NodeHolder.ensureStarted(applicationContext)
                NodeHolder.get(applicationContext).status().ipv4
            }
        } catch (t: Throwable) {
            Log.e(TAG, "could not read mesh IP before tunnel build", t)
            ""
        }
        // Fall back to the CGNAT base if we have no networks yet, so the tunnel
        // still establishes.
        val tunnelAddr = meshIp.ifBlank { "100.64.0.2" }

        // Point the resolver at the phone's real DNS servers before the tunnel
        // captures all DNS on 100.100.100.53. Without this, non-.ray lookups are
        // refused and public browsing breaks while the VPN is up. Read them from
        // the underlying (non-VPN) network, which is still active pre-establish.
        try {
            val dns = systemDnsServers()
            if (dns.isNotEmpty()) {
                NodeHolder.get(applicationContext).setDnsUpstreams(dns)
                Log.i(TAG, "DNS upstreams set: $dns")
            } else {
                Log.w(TAG, "no underlying IPv4 DNS servers found; only .ray will resolve")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "could not set DNS upstreams; only .ray will resolve", t)
        }

        val builder = Builder()
            .setSession("Rayfish")
            .addAddress(tunnelAddr, 32)
            .addRoute("100.64.0.0", 10)
            .addDnsServer("100.100.100.53")
            .addSearchDomain("ray")
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
                NodeHolder.get(applicationContext).up(pfd.detachFd())
                Log.i(TAG, "Node.up succeeded")
            } catch (t: Throwable) {
                Log.e(TAG, "Node bring-up failed", t)
            }
        }
    }

    // The IPv4 DNS servers of the underlying (non-VPN) network, deduplicated.
    // Enumerating all networks and skipping the VPN transport avoids reading our
    // own tunnel's DNS (100.100.100.53) back, which would loop. IPv6-only
    // resolvers are skipped: the mesh resolver forwards over IPv4.
    private fun systemDnsServers(): List<String> {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val servers = mutableListOf<String>()
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val props = cm.getLinkProperties(network) ?: continue
            for (addr in props.dnsServers) {
                if (addr !is Inet4Address) continue
                val ip = addr.hostAddress ?: continue
                if (ip !in servers) servers.add(ip)
            }
        }
        return servers
    }

    private fun stopTunnel() {
        // Disable on mobile means go offline, not standby: tear the whole control
        // plane down (cancels the daemon shutdown token, closes the endpoint) so
        // the device drops out of the mesh immediately. stopNode also clears the
        // started flag so a later enable rebuilds the daemon.
        try {
            NodeHolder.stopNode(applicationContext)
        } catch (t: Throwable) {
            Log.w(TAG, "Node stop failed (may not have been up)", t)
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
