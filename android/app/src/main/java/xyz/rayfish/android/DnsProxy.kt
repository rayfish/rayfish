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
import java.util.concurrent.Executors
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
    private val executor = Executors.newSingleThreadExecutor()

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
            try {
                resolver.rawQuery(
                    network,
                    query,
                    DnsResolver.FLAG_EMPTY,
                    executor,
                    CancellationSignal(),
                    object : DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(answer: ByteArray, rcode: Int) {
                            trySend(answer, client)
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            // A servfail still deserves a DNS reply, but rawQuery
                            // hands us no packet on error; drop and let the client
                            // time out and retry. Logged sparsely to avoid spam.
                            Log.d(TAG, "rawQuery error: ${error.message}")
                        }
                    },
                )
            } catch (t: Throwable) {
                Log.w(TAG, "rawQuery dispatch failed", t)
            }
        }
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
        running = false
        socket.close()
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
