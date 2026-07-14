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
                // Tearing down blocks (a graceful endpoint close on the offline
                // path, so peers see us drop cleanly and a re-enable rebuilds
                // without a stale session). Run it off the main thread to avoid an
                // ANR. In standby we keep the service alive; only the fully-offline
                // path calls stopSelf.
                val standby = NodeHolder.isStayOnline(applicationContext)
                Log.i(TAG, "ACTION_STOP received; standby=$standby (tunnel fd present=${tunnel != null})")
                thread(name = "rayfish-node-stop") {
                    stopTunnel(standby)
                    if (!standby) {
                        Log.i(TAG, "stopTunnel returned; calling stopSelf()")
                        stopSelf()
                    }
                }
                return if (standby) START_STICKY else START_NOT_STICKY
            }
            // A null intent means the system restarted us after killing the process
            // (START_STICKY). No Activity ran, so nothing else brought the node up:
            // decide from the persisted prefs what state to restore.
            null -> {
                if (NodeHolder.isEnabled(applicationContext)) {
                    startTunnel()
                } else if (NodeHolder.isStayOnline(applicationContext)) {
                    enterStandby()
                } else {
                    // Neither the VPN nor stay-online is wanted: nothing to run.
                    stopSelf()
                    return START_NOT_STICKY
                }
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

        startAutoAcceptPoller()
    }

    /**
     * Control plane up, no tunnel. The service stays foreground (Android kills the
     * process, and the tokio runtime with it, once no foreground service is left),
     * so the node keeps serving files and stays visible in the mesh.
     */
    private fun enterStandby() {
        startForegroundNotification(standby = true)
        thread(name = "rayfish-node-standby") {
            try {
                runBlocking { NodeHolder.ensureStarted(applicationContext) }
                Log.i(TAG, "standby: control plane up, no tunnel")
            } catch (t: Throwable) {
                Log.e(TAG, "standby bring-up failed", t)
            }
        }
        startAutoAcceptPoller()
    }

    /**
     * Android revoked our VPN, which happens when another VPN app (Tailscale, say)
     * takes the single VpnService slot, or the user disconnects us from system
     * Settings. The default implementation calls stopSelf(), which would take the
     * whole node offline and defeat the stay-online pref, since this path never
     * touches our own toggle. Route it to the same place the toggle goes.
     */
    override fun onRevoke() {
        val standby = NodeHolder.isStayOnline(applicationContext)
        Log.i(TAG, "onRevoke: VPN revoked by the system; standby=$standby")
        // The user did not ask for the tunnel any more, so clear the enable intent.
        // Otherwise a later app launch would re-establish it and yank the VPN slot
        // back from whatever took it.
        NodeHolder.setEnabled(applicationContext, false)
        thread(name = "rayfish-node-revoke") {
            stopTunnel(standby)
            if (!standby) stopSelf()
        }
    }

    /**
     * Auto-accept own-device file offers, so a file shared to this device from one
     * of the user's own devices lands in Downloads without the app being open. Runs
     * in standby too: that is what makes files keep working with the VPN off. Gated
     * by the user's opt-out toggle inside FileAutoAccept.run. Idempotent.
     */
    private fun startAutoAcceptPoller() {
        if (autoAcceptPoller != null) return
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

    /**
     * Bring the tunnel down. In standby the control plane survives (Node.down):
     * files keep flowing and the device stays online in the mesh. Otherwise this is
     * a full offline teardown (Node.stop), which also clears NodeHolder.started so
     * a later enable rebuilds the daemon.
     */
    private fun stopTunnel(standby: Boolean) {
        try {
            if (standby) {
                Log.i(TAG, "stopTunnel: Node.down (standby, control plane stays up)")
                NodeHolder.downNode(applicationContext)
            } else {
                Log.i(TAG, "stopTunnel: NodeHolder.stopNode (offline)")
                NodeHolder.stopNode(applicationContext)
            }
            Log.i(TAG, "stopTunnel: teardown returned")
        } catch (t: Throwable) {
            Log.w(TAG, "Node teardown failed (may not have been up)", t)
        }
        try {
            // Detached to Rust via detachFd(), so this is a no-op; the fd is only
            // closed when the Rust side aborts the TUN tasks. Logged to make that
            // explicit while debugging a lingering interface.
            Log.i(TAG, "stopTunnel: tunnel?.close() (no-op; fd owned by Rust after detachFd)")
            tunnel?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "closing tunnel fd failed", t)
        }
        tunnel = null

        // The DNS proxy exists to serve the tunnel's resolver; with no tunnel there
        // is nothing pointed at it. Torn down in both cases.
        dnsProxy?.stop()
        dnsProxy = null

        if (standby) {
            // Keep the poller running (files still work) and tell the user plainly
            // what state we are in, so the persistent notification is not confusing.
            startForegroundNotification(standby = true)
        } else {
            autoAcceptPoller?.shutdownNow()
            autoAcceptPoller = null
        }
    }

    override fun onDestroy() {
        // The service is going away for good, so there is no standby to hold: a
        // standby with no foreground service is exactly the process the OS kills.
        // Tear the node down fully.
        Log.i(TAG, "onDestroy: service being destroyed (tunnel fd present=${tunnel != null})")
        stopTunnel(standby = false)
        super.onDestroy()
    }

    private fun startForegroundNotification(standby: Boolean = false) {
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
            .setContentText(if (standby) "Online, VPN off · files still work" else "Mesh tunnel active")
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
