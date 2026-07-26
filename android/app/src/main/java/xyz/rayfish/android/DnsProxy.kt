package xyz.rayfish.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import io.sentry.android.core.SentryLogcatAdapter as Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * A tiny loopback UDP DNS proxy that forwards each raw query through
 * [DnsResolver.rawQuery] on the underlying (non-VPN) network. `rawQuery` goes
 * through the platform resolver, so it honors the device's Private DNS setting
 * (DoT/DoH) instead of downgrading to cleartext UDP on port 53.
 *
 * The Rust Magic DNS resolver forwards every non-`.ray` lookup here (its upstream
 * is set to `127.0.0.1:<port>`); we hand the bytes to the system resolver and
 * write the answer straight back to the caller. Requires API 29
 * ([Build.VERSION_CODES.Q]); on older devices [start] returns null and the caller
 * falls back to the plaintext upstream path.
 */
@RequiresApi(Build.VERSION_CODES.Q)
class DnsProxy private constructor(
    private val socket: DatagramSocket,
    private val resolver: DnsResolver,
    private val context: Context,
) {
    /** The loopback port the proxy is bound to; pass `127.0.0.1:<port>` to Rust. */
    val port: Int get() = socket.localPort

    @Volatile
    private var running = true

    // rawQuery callbacks land here; a single thread serializes the socket sends.
    //
    // Built by hand rather than via Executors.newSingleThreadExecutor() for the
    // rejected-execution policy: the default is AbortPolicy, which throws. A query
    // still in flight when stop() shuts this down has already registered an fd
    // listener with the platform resolver, and the platform delivers its answer by
    // posting here. That post happens on the main looper, inside DnsResolver's own
    // frames with none of ours on the stack, so an AbortPolicy throw reaches the
    // default uncaught-exception handler and kills the process (the try/catch
    // around rawQuery below only covers the dispatch, never the later callback).
    // DiscardPolicy drops the late answer instead, which is the right outcome: the
    // socket it would have been written to is closed by then anyway.
    private val executor = ThreadPoolExecutor(
        1, 1,
        0L, TimeUnit.MILLISECONDS,
        LinkedBlockingQueue(),
        { r -> Thread(r, "rayfish-dns-proxy-cb").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardPolicy(),
    )

    // CancellationSignals for queries that have been dispatched but whose callback
    // has not fired yet. stop() cancels them so the platform tears the lookups down
    // instead of leaving them to complete against a dead proxy. Guarded by its own
    // lock: entries are added on the receive loop's thread and removed on the
    // executor thread.
    private val inFlight = mutableSetOf<CancellationSignal>()

    private fun loop() {
        val buf = ByteArray(4096)
        while (running) {
            val request = DatagramPacket(buf, buf.size)
            try {
                socket.receive(request)
            } catch (t: Throwable) {
                if (running) Log.w(TAG, "dns proxy receive failed", t)
                break
            }
            val query = request.data.copyOfRange(0, request.length)
            val client = request.socketAddress
            val network = underlyingNetwork()
            val signal = CancellationSignal()
            // Registered before dispatch, not after: stop() can land in between,
            // and a signal added afterwards would miss the cancellation sweep and
            // leave the lookup running against a closed socket.
            if (!register(signal)) break
            try {
                resolver.rawQuery(
                    network,
                    query,
                    DnsResolver.FLAG_EMPTY,
                    executor,
                    signal,
                    object : DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(answer: ByteArray, rcode: Int) {
                            unregister(signal)
                            trySend(answer, client)
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            unregister(signal)
                            // A servfail still deserves a DNS reply, but rawQuery
                            // hands us no packet on error; drop and let the client
                            // time out and retry. Logged sparsely to avoid spam.
                            Log.d(TAG, "rawQuery error: ${error.message}")
                        }
                    },
                )
            } catch (t: Throwable) {
                unregister(signal)
                Log.w(TAG, "rawQuery dispatch failed", t)
            }
        }
    }

    // Track a query about to be dispatched. Returns false if the proxy has already
    // been stopped, in which case the caller must not dispatch: `running` is read
    // and written under the same lock that guards the set, so a query can never
    // slip in after stop()'s sweep has run.
    private fun register(signal: CancellationSignal): Boolean = synchronized(inFlight) {
        if (!running) return false
        inFlight.add(signal)
        true
    }

    private fun unregister(signal: CancellationSignal) {
        synchronized(inFlight) { inFlight.remove(signal) }
    }

    private fun trySend(answer: ByteArray, client: java.net.SocketAddress) {
        try {
            socket.send(DatagramPacket(answer, answer.size, client))
        } catch (t: Throwable) {
            if (running) Log.w(TAG, "dns proxy send failed", t)
        }
    }

    // The active underlying network, or the first non-VPN network with internet.
    // rawQuery(network=null) would use our app's default network, which is already
    // the underlying one once the app is excluded from its own VPN; resolving it
    // explicitly keeps us correct regardless of exclusion ordering.
    private fun underlyingNetwork(): Network? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            return network
        }
        return null
    }

    fun stop() {
        // Take the in-flight queries and close the door on new ones in one step, so
        // the receive loop cannot register another between the sweep and the
        // shutdown below (see register()).
        val pending = synchronized(inFlight) {
            running = false
            inFlight.toList().also { inFlight.clear() }
        }
        socket.close()
        // Cancelling unregisters the platform's fd listener, so the lookup is torn
        // down rather than left to deliver an answer nobody can use. Cancelling an
        // already-completed query is a no-op. Done before the executor shutdown so
        // the common case never reaches the DiscardPolicy at all; that policy stays
        // as the backstop for an answer that was already posted here.
        for (signal in pending) {
            try {
                signal.cancel()
            } catch (t: Throwable) {
                Log.w(TAG, "cancelling an in-flight DNS query failed", t)
            }
        }
        executor.shutdownNow()
    }

    companion object {
        private const val TAG = "RayfishDnsProxy"

        /**
         * Bind the proxy to an ephemeral loopback port and start its receive loop.
         * Returns null on API < 29 (no [DnsResolver]) or if binding fails; the
         * caller then falls back to the plaintext upstream path.
         */
        fun start(context: Context): DnsProxy? {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
            return try {
                val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                val proxy = DnsProxy(socket, DnsResolver.getInstance(), context.applicationContext)
                thread(name = "rayfish-dns-proxy", isDaemon = true) { proxy.loop() }
                Log.i(TAG, "DNS proxy listening on 127.0.0.1:${proxy.port}")
                proxy
            } catch (t: Throwable) {
                Log.e(TAG, "could not start DNS proxy; falling back to plaintext DNS", t)
                null
            }
        }
    }
}
