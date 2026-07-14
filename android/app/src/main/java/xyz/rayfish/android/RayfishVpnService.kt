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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
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
    private var autoAcceptPoller: ScheduledExecutorService? = null

    // Serializes bring-up (startTunnel/enterStandby) and teardown (stopTunnel) so
    // they can never interleave. Both read and write the tunnel/dnsProxy fields;
    // running them on the same single-threaded executor means a queued task only
    // starts once the previous one has fully finished, so an off-then-on always
    // ends with the tunnel up and an on-then-off always ends in standby/offline,
    // regardless of how quickly the two requests arrive. Neither task may run on
    // the main thread: both block on FFI calls into the Rust core.
    private val nodeExecutor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            // A genuinely null intent means the system restarted us after killing
            // the process (START_STICKY re-delivery). No Activity ran, so nothing
            // else brought the node up: decide from the persisted prefs what
            // state to restore.
            if (NodeHolder.isEnabled(applicationContext)) {
                startTunnel(startId)
            } else if (NodeHolder.isStayOnline(applicationContext)) {
                enterStandby()
            } else {
                // Neither the VPN nor stay-online is wanted: nothing to run.
                stopSelf()
                return START_NOT_STICKY
            }
            return START_STICKY
        }

        when (intent.action) {
            ACTION_STOP -> {
                // Tearing down blocks (a graceful endpoint close on the offline
                // path, so peers see us drop cleanly and a re-enable rebuilds
                // without a stale session). Run it on the node executor to avoid
                // an ANR and to serialize with any concurrent bring-up. In
                // standby we keep the service alive; only the fully-offline path
                // calls stopSelf.
                val standby = NodeHolder.isStayOnline(applicationContext)
                Log.i(TAG, "ACTION_STOP received; standby=$standby (tunnel fd present=${tunnel != null})")
                if (standby) {
                    // Post the standby text now, not after the blocking teardown
                    // below returns, so the notification does not keep reading
                    // "Mesh tunnel active" while downNode() is still running.
                    startForegroundNotification(standby = true)
                }
                nodeExecutor.execute {
                    // A Runnable submitted with execute() has no Future to surface a
                    // throw through; an uncaught one reaches the default
                    // uncaught-exception handler and kills the process, which is
                    // worse than whatever this task was trying to clean up. Catch
                    // and log instead of letting that happen.
                    try {
                        stopTunnel(standby)
                        if (!standby) {
                            // stopSelf(startId), not the bare stopSelf(): fast off-then-on
                            // toggling queues this stop behind a start that already
                            // landed. stopSelf(startId) is a no-op once a newer start
                            // command has been delivered, so it only kills the service
                            // if no start arrived after this one; the bare form would
                            // kill it either way and undo the newer start's tunnel.
                            Log.i(TAG, "stopTunnel returned; calling stopSelf(startId=$startId)")
                            stopSelf(startId)
                        }
                    } catch (t: Throwable) {
                        Log.e(TAG, "ACTION_STOP task crashed", t)
                    }
                }
                return if (standby) START_STICKY else START_NOT_STICKY
            }
            ACTION_STANDBY -> {
                // "Keep files working when the VPN is off", started explicitly
                // from YouScreen while the tunnel is off. Must bring up the
                // control plane only: never touch the Builder/establish() path,
                // so it never contends for the single VpnService slot and never
                // triggers the VPN consent dialog. enterStandby() is idempotent,
                // so a repeat call (fast toggle off-then-on) is harmless.
                Log.i(TAG, "ACTION_STANDBY received")
                if (tunnel != null) {
                    // The tunnel is already up: this is a pref-flip racing with a live
                    // tunnel, not the "VPN is off, bring up the control plane only"
                    // case this action exists for. Never tear a live tunnel down
                    // because of it.
                    Log.i(TAG, "ACTION_STANDBY ignored: tunnel already up")
                    return START_STICKY
                }
                enterStandby()
                return START_STICKY
            }
            // An action-less start intent is the normal "turn the VPN on" path
            // (see HomeScreen / RayfishApp, which both start the service with a
            // plain Intent). It must reach startTunnel(), not be mistaken for
            // the null-intent restart-recovery branch above.
            else -> startTunnel(startId)
        }
        return START_STICKY
    }

    private fun startTunnel(startId: Int) {
        // startForeground must be called promptly so the foreground-service
        // deadline is met; only the blocking node work goes to the executor.
        startForegroundNotification()
        nodeExecutor.execute {
            // See the ACTION_STOP execute() block for why this must never let a
            // throwable escape: an uncaught one here kills the process outright.
            try {
                startTunnelBlocking(startId)
            } catch (t: Throwable) {
                Log.e(TAG, "startTunnelBlocking task crashed", t)
            }
        }
    }

    private fun startTunnelBlocking(startId: Int) {
        if (tunnel != null) return

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

        // The whole Builder chain and establish() are one try block so a single
        // failure handler covers both. addAddress()/addRoute() throw
        // IllegalArgumentException on a malformed address (tunnelAddr/meshV6 come
        // from status() and are only blank-checked, not validated), and
        // establish() can return null. Both must land in the same pfd == null
        // path below: previously a Builder throw escaped that path entirely and
        // was swallowed by the outer executor catch, leaving dnsProxy set with no
        // tunnel to serve and no standby fallback.
        var builderThrew = false
        val pfd = try {
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
            // Exclude Rayfish itself from its own tunnel. Its sockets (the iroh
            // mesh underlay, the DnsResolver.rawQuery proxy) then use the real
            // underlying network directly, so DNS forwarding can't loop back
            // through the TUN and Private DNS keeps working. Split routing
            // already keeps mesh traffic on the tunnel via the Rust core's fd,
            // not the app's normal sockets.
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: PackageManager.NameNotFoundException) {
                Log.w(TAG, "could not exclude self from VPN: $packageName")
            }

            // Keep VPN-hostile apps (Android Auto, casting, RCS, Sonos) off the
            // tunnel. Each add is guarded: an uninstalled package must not abort
            // setup.
            for (pkg in DISALLOWED_APPS) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (_: PackageManager.NameNotFoundException) {
                    Log.i(TAG, "disallowed app not installed, skipping: $pkg")
                }
            }

            builder.establish()
        } catch (t: Throwable) {
            Log.e(TAG, "VpnService.Builder chain or establish() threw", t)
            builderThrew = true
            null
        }
        if (pfd == null) {
            // establish() returns null precisely when we do not hold the single
            // VpnService slot (another VPN app, e.g. Tailscale, took it, or the
            // user has none configured); a Builder throw (malformed address) is
            // the other way this branch is reached. Either way there is no
            // tunnel, so this goes through the same recovery as a failed
            // Node.up() below: see handleBringUpFailure.
            val reason = if (builderThrew) {
                "VpnService.Builder chain threw"
            } else {
                "VpnService.Builder.establish() returned null (VPN slot likely unavailable)"
            }
            handleBringUpFailure(reason, startId)
            return
        }
        tunnel = pfd

        // Node.up drives the blocking-ish bring-up (endpoint bind, forward loop
        // spawn); called inline here, on nodeExecutor's own thread, so it is
        // fully done (tunnel attached or not) before the next queued task (a
        // stop, say) can run. A detached thread would return before Node.up
        // ran, letting a later stopTunnel's down() race ahead of it: a stale
        // up() would then re-attach the TUN after the user asked for it off.
        // detachFd() transfers ownership of the tunnel fd to the Rust side,
        // which closes it on Node.down; our ParcelFileDescriptor no longer
        // owns an fd, so tunnel?.close() on stop is a harmless no-op kept only
        // to clear the reference.
        //
        // ensureStarted() MUST run before up(): the node needs start() (which
        // builds the headless daemon and reconnects saved networks) or up()
        // returns NotStarted. The service is START_STICKY, so the system can
        // restart it with no Activity ever created and the UI's ensureStarted
        // never running; starting it here makes the service self-sufficient.
        try {
            NodeHolder.get(applicationContext).up(pfd.detachFd())
            Log.i(TAG, "Node.up succeeded")
            startAutoAcceptPoller()
        } catch (t: Throwable) {
            Log.e(TAG, "Node bring-up failed", t)
            // up() threw after detachFd() handed the fd to Rust, so this
            // ParcelFileDescriptor no longer owns anything worth keeping around.
            // This is the third way tunnel bring-up can fail (the other two are
            // establish() returning null and the Builder chain throwing, above):
            // it needs exactly the same recovery, so it goes through the same
            // helper instead of a divergent one that leaves dnsProxy orphaned and
            // the notification claiming a tunnel that isn't there.
            handleBringUpFailure("Node.up() threw", startId)
        }
    }

    /**
     * Common recovery for every way tunnel bring-up can fail: establish()
     * returning null, the Builder chain throwing, or Node.up() throwing. Stops
     * and clears dnsProxy (nothing left to serve; leaving it running leaks a
     * bound socket and a thread on every retry of startTunnelBlocking, since
     * DnsProxy.start() overwrites the field without stopping the old one).
     * tunnel is left null so a retry can rebuild the tunnel from scratch
     * instead of needing a full stop first.
     *
     * Then: with stay-online on, this is exactly the case standby exists for,
     * so the control plane must actually be (re)brought up here: the caller may
     * have reached this point via a failed ensureStarted followed by a
     * establish()/Node.up() that never needed the node running (see
     * startTunnelBlocking's fallback tunnel address), so it cannot be assumed
     * already up. ensureStarted is idempotent, so this is a no-op in the
     * common case where it is. Once that is done, the standby notification
     * replaces whatever startForegroundNotification() posted at the top of
     * startTunnel(), and the poller starts so files keep landing. With
     * stay-online off there is nothing left to keep the service alive for.
     */
    private fun handleBringUpFailure(reason: String, startId: Int) {
        tunnel = null
        try {
            dnsProxy?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "dnsProxy.stop() failed during bring-up failure recovery", t)
        }
        dnsProxy = null

        val standby = NodeHolder.isStayOnline(applicationContext)
        if (standby) {
            Log.w(TAG, "$reason; staying in standby, ensuring control plane is up")
            try {
                runBlocking { NodeHolder.ensureStarted(applicationContext) }
            } catch (t: Throwable) {
                Log.e(TAG, "handleBringUpFailure: ensureStarted failed; mesh visibility and file transfer will not work until this recovers", t)
            }
            startForegroundNotification(standby = true)
            startAutoAcceptPoller()
        } else {
            Log.e(TAG, "$reason; tunnel not up, stopping service (startId=$startId)")
            stopSelf(startId)
        }
    }

    /**
     * Control plane up, no tunnel. The service stays foreground (Android kills the
     * process, and the tokio runtime with it, once no foreground service is left),
     * so the node keeps serving files and stays visible in the mesh.
     */
    private fun enterStandby() {
        startForegroundNotification(standby = true)
        nodeExecutor.execute {
            // Outer catch: see the ACTION_STOP execute() block. The inner catch
            // below is deliberately narrower: a control-plane bring-up failure
            // still needs the poller started, so it's caught and logged there
            // rather than aborting this whole task.
            try {
                try {
                    runBlocking { NodeHolder.ensureStarted(applicationContext) }
                    Log.i(TAG, "standby: control plane up, no tunnel")
                } catch (t: Throwable) {
                    Log.e(TAG, "standby bring-up failed", t)
                }
                // Moved inside the executor task: autoAcceptPoller (like dnsProxy) is
                // only read and written from nodeExecutor's thread (startTunnelBlocking,
                // stopTunnel). Calling this from the main thread, as before, made it the
                // one field touched from two threads with no lock between them.
                startAutoAcceptPoller()
            } catch (t: Throwable) {
                Log.e(TAG, "enterStandby task crashed", t)
            }
        }
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
        if (standby) {
            // Post the standby text now, not after the blocking teardown below
            // returns (see the same fix in the ACTION_STOP path above).
            startForegroundNotification(standby = true)
        }
        nodeExecutor.execute {
            // See the ACTION_STOP execute() block for why this must never let a
            // throwable escape.
            try {
                stopTunnel(standby)
                if (!standby) stopSelf()
            } catch (t: Throwable) {
                Log.e(TAG, "onRevoke task crashed", t)
            }
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
        autoAcceptPoller = Executors.newSingleThreadScheduledExecutor().also { exec ->
            exec.scheduleWithFixedDelay(
                { runCatching { FileAutoAccept.run(applicationContext) } },
                4, 4, TimeUnit.SECONDS,
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
     *
     * Always runs on [nodeExecutor], serialized with [startTunnelBlocking]: the
     * standby notification text is posted by the caller before this runs, not
     * here, so it flips the instant the request lands instead of only once this
     * blocking teardown returns.
     */
    private fun stopTunnel(standby: Boolean) {
        try {
            if (standby) {
                // NodeHolder.started is a process-level flag and RayfishApp
                // deliberately never calls ensureStarted (it only observes), so
                // ACTION_STOP/onRevoke can reach this branch on a fresh service
                // instance where the node was never started (e.g. the VPN slot
                // was already taken when the app launched, so the service never
                // ran startTunnelBlocking). Without this, downNode() below is a
                // no-op, the poller starts polling a node that was never up, and
                // the notification we already posted ("Online, VPN off · files
                // still work") is a lie. Idempotent, so this is a no-op if the
                // node is already started.
                try {
                    runBlocking { NodeHolder.ensureStarted(applicationContext) }
                } catch (t: Throwable) {
                    Log.e(TAG, "stopTunnel: standby ensureStarted failed; mesh visibility and file transfer will not work until this recovers", t)
                }
                Log.i(TAG, "stopTunnel: Node.down (standby, control plane stays up)")
                NodeHolder.downNode(applicationContext)
                // Every standby path must start the poller by construction, not
                // rely on some earlier path in the same process having already
                // started it. ACTION_STOP and onRevoke can both reach standby on
                // a service instance where the node was never started (a fresh
                // instance from HomeScreen's context.startService, say), in which
                // case downNode() above is a no-op and nothing else here would
                // start it. Idempotent, so this is a no-op when it is already
                // running.
                startAutoAcceptPoller()
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
        // is nothing pointed at it. Torn down in both cases. Wrapped: this runs on
        // nodeExecutor via execute(), so an uncaught throwable here would reach the
        // default uncaught-exception handler and kill the process, skipping the
        // dnsProxy = null reset and the poller shutdown below.
        try {
            dnsProxy?.stop()
        } catch (t: Throwable) {
            Log.w(TAG, "dnsProxy.stop() failed", t)
        }
        dnsProxy = null

        // Keep the poller running in standby (files still work); shut it down on a
        // full offline teardown.
        if (!standby) {
            autoAcceptPoller?.shutdownNow()
            autoAcceptPoller = null
        }
    }

    override fun onDestroy() {
        // The service is going away for good, so there is no standby to hold: a
        // standby with no foreground service is exactly the process the OS kills.
        // Tear the node down fully. Routed through nodeExecutor (not called
        // inline) so it cannot interleave with a bring-up task still running or
        // queued there; it queues behind whatever is already there instead.
        //
        // Not waited on: onDestroy runs on the main thread under a 20s
        // foreground-service ANR deadline, and the queue ahead of this task can
        // include a full startTunnelBlocking (RustlsInit, Node.start binding the
        // iroh endpoint and reconnecting saved networks: seconds, network-
        // dependent) followed by this teardown, which can itself block on a
        // graceful endpoint close. Blocking here bought nothing anyway: the
        // process outlives onDestroy and nodeExecutor.shutdown() below already
        // lets every queued task, including this one, run to completion in the
        // background.
        Log.i(TAG, "onDestroy: service being destroyed (tunnel fd present=${tunnel != null})")
        nodeExecutor.execute {
            // See the ACTION_STOP execute() block for why this must never let a
            // throwable escape.
            try {
                stopTunnel(standby = false)
            } catch (t: Throwable) {
                Log.e(TAG, "onDestroy teardown task crashed", t)
            }
        }
        nodeExecutor.shutdown()
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
        const val ACTION_STANDBY = "xyz.rayfish.android.STANDBY"

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
