package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
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
    // Loopback DNS proxy forwarding non-.ray lookups through DnsResolver.rawQuery
    // (honors Private DNS / DoT). Null on API < 29 or if it failed to start.
    private var dnsProxy: DnsProxy? = null
    // Polls for incoming own-device file offers and auto-accepts them, so files
    // shared to this device land in Downloads even with the app UI closed.
    private var autoAcceptPoller: java.util.concurrent.ScheduledExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // stopTunnel now blocks on a graceful endpoint close (so peers
                // see us drop cleanly and re-enable rebuilds without a stale
                // session). Run it off the main thread to avoid an ANR, then
                // stop the service.
                Log.i(TAG, "ACTION_STOP received; tearing tunnel down (tunnel fd present=${tunnel != null})")
                thread(name = "rayfish-node-stop") {
                    stopTunnel()
                    Log.i(TAG, "stopTunnel returned; calling stopSelf()")
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
        val (meshIp, meshV6) = try {
            runBlocking {
                NodeHolder.ensureStarted(applicationContext)
                val snapshot = NodeHolder.get(applicationContext).status()
                snapshot.ipv4 to snapshot.ipv6
            }
        } catch (t: Throwable) {
            Log.e(TAG, "could not read mesh IP before tunnel build", t)
            "" to ""
        }
        // Fall back to the CGNAT base if we have no networks yet, so the tunnel
        // still establishes.
        val tunnelAddr = meshIp.ifBlank { "100.64.0.2" }

        // Point the resolver at the phone's real DNS before the tunnel captures
        // all DNS on 100.100.100.53. Without this, non-.ray lookups are refused
        // and public browsing breaks while the VPN is up.
        //
        // Prefer a loopback DnsResolver.rawQuery proxy: it forwards through the
        // platform resolver, so it honors the device's Private DNS (DoT/DoH)
        // instead of downgrading to cleartext UDP:53. Only when the proxy is
        // unavailable (API < 29 or bind failure) do we fall back to handing the
        // underlying network's plaintext IPv4 resolvers straight to Rust.
        try {
            val proxy = DnsProxy.start(applicationContext)
            dnsProxy = proxy
            if (proxy != null) {
                NodeHolder.get(applicationContext).setDnsUpstreams(listOf("127.0.0.1:${proxy.port}"))
                Log.i(TAG, "DNS upstream set to rawQuery proxy 127.0.0.1:${proxy.port}")
            } else {
                val dns = systemDnsServers()
                if (dns.isNotEmpty()) {
                    NodeHolder.get(applicationContext).setDnsUpstreams(dns)
                    Log.i(TAG, "DNS upstreams set (plaintext fallback): $dns")
                } else {
                    Log.w(TAG, "no underlying IPv4 DNS servers found; only .ray will resolve")
                }
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

        // Route the mesh IPv6 range through the tunnel (mirrors the desktop
        // 200::/7 route). Skipped if we have no v6 address to bind.
        if (meshV6.isNotBlank()) {
            builder.addAddress(meshV6, 128)
            builder.addRoute("200::", 7)
        }
        // Exclude Rayfish itself from its own tunnel. Its sockets (the iroh mesh
        // underlay, the DnsResolver.rawQuery proxy) then use the real underlying
        // network directly, so DNS forwarding can't loop back through the TUN and
        // Private DNS keeps working. Split routing already keeps mesh traffic on
        // the tunnel via the Rust core's fd, not the app's normal sockets.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            Log.w(TAG, "could not exclude self from VPN: $packageName")
        }

        // Keep VPN-hostile apps (Android Auto, casting, RCS, Sonos) off the
        // tunnel. Each add is guarded: an uninstalled package must not abort setup.
        for (pkg in DISALLOWED_APPS) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                Log.i(TAG, "disallowed app not installed, skipping: $pkg")
            }
        }

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

        // Auto-accept own-device file offers while the tunnel is up, so a file
        // shared to this device from one of the user's own devices lands in
        // Downloads without the app being open. Gated by the user's opt-out toggle
        // inside FileAutoAccept.run.
        autoAcceptPoller = java.util.concurrent.Executors.newSingleThreadScheduledExecutor().also { exec ->
            exec.scheduleWithFixedDelay(
                { runCatching { FileAutoAccept.run(applicationContext) } },
                4, 4, java.util.concurrent.TimeUnit.SECONDS,
            )
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
            Log.i(TAG, "stopTunnel: calling NodeHolder.stopNode (offline)")
            NodeHolder.stopNode(applicationContext)
            Log.i(TAG, "stopTunnel: stopNode returned")
        } catch (t: Throwable) {
            Log.w(TAG, "Node stop failed (may not have been up)", t)
        }
        try {
            // Detached to Rust via detachFd(), so this is a no-op; the fd is only
            // closed when the Rust side aborts the TUN tasks. Logged to make that
            // explicit while debugging the lingering interface.
            Log.i(TAG, "stopTunnel: tunnel?.close() (no-op; fd owned by Rust after detachFd)")
            tunnel?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "closing tunnel fd failed", t)
        }

        autoAcceptPoller?.shutdownNow()
        autoAcceptPoller = null

        dnsProxy?.stop()
        dnsProxy = null

        tunnel = null
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy: service being destroyed (tunnel fd present=${tunnel != null})")
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

        // Apps that misbehave behind a VPN (casting, RCS, local-device discovery).
        // Mirrors Tailscale's default Android exclusions. Excluded so they never
        // see the VPN interface; our tunnel is split (mesh routes only) anyway.
        private val DISALLOWED_APPS = listOf(
            "com.google.android.projection.gearhead", // Android Auto
            "com.google.android.apps.chromecast.app", // Google Home / Chromecast
            "com.google.android.apps.messaging",      // RCS / Jibe messaging
            "com.gopro.smarty",                       // GoPro
            "com.sonos.acr", "com.sonos.acr2",        // Sonos
        )
    }
}
