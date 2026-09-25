package xyz.rayfish.android

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.*
import android.net.wifi.WifiInfo
import android.os.Build

/**
 * Count every callback, but only notify the core when connectivity may have
 * changed. Bandwidth and signal updates can arrive seconds apart on an otherwise
 * unchanged connection; forwarding those also wakes the signed-record pollers.
 * Each registration owns its cache, so default and physical networks cannot
 * overwrite one another's observations.
 */
internal class NetworkChangeCallback(
    private val onEvent: (NetworkEvent, Network, Boolean) -> Unit,
) : ConnectivityManager.NetworkCallback() {
    private val capabilities = mutableMapOf<Network, ConnectionCapabilities>()
    private var active = true

    @Synchronized
    override fun onAvailable(network: Network) {
        if (!active) return
        capabilities.remove(network)
        onEvent(NetworkEvent.AVAILABLE, network, true)
    }

    @Synchronized
    override fun onLost(network: Network) {
        if (!active) return
        capabilities.remove(network)
        onEvent(NetworkEvent.LOST, network, true)
    }

    @Synchronized
    override fun onLinkPropertiesChanged(network: Network, props: LinkProperties) {
        if (!active) return
        // Preserve address, route, DNS and MTU updates, including Wi-Fi roams
        // where Android keeps the same Network object.
        onEvent(NetworkEvent.LINK_PROPERTIES, network, true)
    }

    @Synchronized
    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        if (!active) return
        val next = ConnectionCapabilities.from(caps)
        val previous = capabilities.put(network, next)
        onEvent(NetworkEvent.CAPABILITIES, network, previous != next)
    }

    /** Ignore callbacks already queued when the node unregisters this listener. */
    @Synchronized
    fun deactivate() {
        active = false
        capabilities.clear()
    }
}

private data class ConnectionCapabilities(
    val transports: Set<Int>,
    val reachability: Set<Int>,
    val wifiBssid: String?,
) {
    companion object {
        fun from(caps: NetworkCapabilities): ConnectionCapabilities {
            val transports = buildList {
                addAll(listOf(TRANSPORT_CELLULAR, TRANSPORT_WIFI, TRANSPORT_BLUETOOTH,
                    TRANSPORT_ETHERNET, TRANSPORT_VPN, TRANSPORT_WIFI_AWARE))
                if (Build.VERSION.SDK_INT >= 27) add(TRANSPORT_LOWPAN)
                if (Build.VERSION.SDK_INT >= 31) add(TRANSPORT_USB)
                if (Build.VERSION.SDK_INT >= 34) add(TRANSPORT_THREAD)
                if (Build.VERSION.SDK_INT >= 35) add(TRANSPORT_SATELLITE)
            }.filter(caps::hasTransport).toSet()
            val reachability = buildList {
                addAll(listOf(NET_CAPABILITY_INTERNET, NET_CAPABILITY_VALIDATED,
                    NET_CAPABILITY_CAPTIVE_PORTAL, NET_CAPABILITY_NOT_RESTRICTED))
                if (Build.VERSION.SDK_INT >= 28) add(NET_CAPABILITY_NOT_SUSPENDED)
            }.filter(caps::hasCapability).toSet()
            // A roam can change the access point without replacing the Network.
            // When Android redacts the BSSID it stays constant; link-property
            // callbacks still cover any resulting address or routing changes.
            val bssid = if (Build.VERSION.SDK_INT >= 29) {
                (caps.transportInfo as? WifiInfo)?.bssid
            } else null
            return ConnectionCapabilities(transports, reachability, bssid)
        }
    }
}
