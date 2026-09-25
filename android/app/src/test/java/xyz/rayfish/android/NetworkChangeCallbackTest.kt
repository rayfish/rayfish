package xyz.rayfish.android

import android.app.Application
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.*
import android.os.Build
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowWifiInfo
import org.robolectric.util.ReflectionHelpers
import org.robolectric.util.ReflectionHelpers.ClassParameter

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], application = Application::class)
class NetworkChangeCallbackTest {
    private val wifi = ShadowNetwork.newInstance(620)
    private val events = mutableListOf<Pair<NetworkEvent, Boolean>>()
    private val callback = NetworkChangeCallback { event, _, changed -> events += event to changed }

    private fun capabilities(transport: Int = TRANSPORT_WIFI): NetworkCapabilities =
        NetworkCapabilities().also {
            shadowOf(it).addTransportType(transport)
            shadowOf(it).addCapability(NET_CAPABILITY_INTERNET)
            shadowOf(it).addCapability(NET_CAPABILITY_VALIDATED)
        }

    // Bandwidth/signal setters are hidden platform APIs. Use real Android
    // objects under Robolectric so this tests which fields the callback reads.
    private fun setMetric(caps: NetworkCapabilities, method: String, value: Int) {
        ReflectionHelpers.callInstanceMethod<Any>(
            caps, method, ClassParameter.from(Int::class.javaPrimitiveType!!, value),
        )
    }

    @Test
    fun bandwidthAndSignalUpdatesAreCountedWithoutNotifyingCore() {
        val caps = capabilities()
        shadowOf(caps).addTransportType(TRANSPORT_VPN)
        callback.onCapabilitiesChanged(wifi, caps)
        repeat(20) { i ->
            setMetric(caps, "setLinkUpstreamBandwidthKbps", 12259 + i)
            setMetric(caps, "setLinkDownstreamBandwidthKbps", 73509 - i)
            if (Build.VERSION.SDK_INT >= 29) setMetric(caps, "setSignalStrength", -60 - i)
            callback.onCapabilitiesChanged(wifi, caps)
        }
        assertEquals(21, events.size)
        assertEquals(1, events.count { it.second })
    }

    @Test
    fun validationAndCaptivePortalTransitionsStillNotify() {
        val caps = capabilities()
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(caps).removeCapability(NET_CAPABILITY_VALIDATED)
        shadowOf(caps).addCapability(NET_CAPABILITY_CAPTIVE_PORTAL)
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(caps).removeCapability(NET_CAPABILITY_CAPTIVE_PORTAL)
        shadowOf(caps).addCapability(NET_CAPABILITY_VALIDATED)
        callback.onCapabilitiesChanged(wifi, caps)
        assertEquals(listOf(true, true, true), events.map { it.second })
    }

    @Test
    @Config(sdk = [35])
    fun suspensionAndResumeStillNotify() {
        val caps = capabilities()
        shadowOf(caps).addCapability(NET_CAPABILITY_NOT_SUSPENDED)
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(caps).removeCapability(NET_CAPABILITY_NOT_SUSPENDED)
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(caps).addCapability(NET_CAPABILITY_NOT_SUSPENDED)
        callback.onCapabilitiesChanged(wifi, caps)
        assertEquals(listOf(true, true, true), events.map { it.second })
    }

    @Test
    fun vpnTransportHandoverStillNotifies() {
        val vpn = ShadowNetwork.newInstance(602)
        val caps = capabilities()
        shadowOf(caps).addTransportType(TRANSPORT_VPN)
        callback.onCapabilitiesChanged(vpn, caps)
        shadowOf(caps).removeTransportType(TRANSPORT_WIFI)
        shadowOf(caps).addTransportType(TRANSPORT_CELLULAR)
        callback.onCapabilitiesChanged(vpn, caps)
        assertEquals(listOf(true, true), events.map { it.second })
    }

    @Test
    fun physicalNetworksHaveIndependentStateAndForgetLostNetworks() {
        val otherWifi = ShadowNetwork.newInstance(621)
        val caps = capabilities()
        callback.onCapabilitiesChanged(wifi, caps)
        callback.onCapabilitiesChanged(otherWifi, caps)
        callback.onCapabilitiesChanged(wifi, caps)
        callback.onLost(wifi)
        callback.onAvailable(wifi)
        callback.onCapabilitiesChanged(wifi, caps)
        assertEquals(listOf(true, true, false, true, true, true), events.map { it.second })
    }

    @Test
    fun addressAndDnsChangesStillNotifyWithUnchangedCapabilities() {
        val caps = capabilities()
        callback.onCapabilitiesChanged(wifi, caps)
        val props = LinkProperties().apply {
            interfaceName = "wlan0"
        }
        addAddress(props, "192.0.2.1/24")
        callback.onLinkPropertiesChanged(wifi, props)
        ReflectionHelpers.callInstanceMethod<Boolean>(props, "addDnsServer",
            ClassParameter.from(InetAddress::class.java, InetAddress.getByName("192.0.2.53")))
        callback.onLinkPropertiesChanged(wifi, props)
        addAddress(props, "2001:db8::1/64")
        callback.onLinkPropertiesChanged(wifi, props)
        callback.onCapabilitiesChanged(wifi, caps)
        assertEquals(listOf(true, true, true, true, false), events.map { it.second })
    }

    private fun addAddress(props: LinkProperties, address: String) {
        val (ip, prefix) = address.split('/')
        val linkAddress = ReflectionHelpers.callConstructor(LinkAddress::class.java,
            ClassParameter.from(InetAddress::class.java, InetAddress.getByName(ip)),
            ClassParameter.from(Int::class.javaPrimitiveType!!, prefix.toInt()))
        ReflectionHelpers.callInstanceMethod<Boolean>(props, "addLinkAddress",
            ClassParameter.from(LinkAddress::class.java, linkAddress))
    }

    @Test
    @Config(sdk = [35])
    fun wifiRoamNotifiesButWifiSignalAndLinkSpeedDoNot() {
        val info = ShadowWifiInfo.newInstance()
        shadowOf(info).setBSSID("02:00:00:00:00:01")
        val caps = capabilities()
        shadowOf(caps).setTransportInfo(info)
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(info).setRssi(-70)
        shadowOf(info).setLinkSpeed(100)
        callback.onCapabilitiesChanged(wifi, caps)
        shadowOf(info).setBSSID("02:00:00:00:00:02")
        callback.onCapabilitiesChanged(wifi, caps)
        assertEquals(listOf(true, false, true), events.map { it.second })
    }

    @Test
    fun queuedCallbacksAfterUnregisterDoNotRestartWork() {
        callback.onCapabilitiesChanged(wifi, capabilities())
        callback.deactivate()
        events.clear()
        callback.onAvailable(wifi)
        callback.onCapabilitiesChanged(wifi, capabilities(TRANSPORT_CELLULAR))
        callback.onLinkPropertiesChanged(wifi, LinkProperties())
        callback.onLost(wifi)
        assertEquals(emptyList<Pair<NetworkEvent, Boolean>>(), events)
    }
}
