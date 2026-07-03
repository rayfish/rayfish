package xyz.rayfish.android.ui.screens

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import uniffi.ray_mobile.Status
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.ui.components.*

@Composable
fun HomeScreen(status: Status?, starting: Boolean, onToast: (String) -> Unit) {
    val context = LocalContext.current
    var vpnOn by remember { mutableStateOf(false) }
    var pendingVpn by remember { mutableStateOf<Boolean?>(null) }

    // Reflect the real data-plane state when status arrives, without stomping an in-flight toggle.
    LaunchedEffect(status?.running) {
        val running = status?.running ?: return@LaunchedEffect
        val pending = pendingVpn
        when {
            pending == null -> vpnOn = running          // no user action in flight: follow the truth
            running == pending -> { vpnOn = running; pendingVpn = null }  // reached desired state: adopt and clear
            // else: still transitioning toward the user's choice - keep the optimistic vpnOn, do not stomp it
        }
    }

    fun startService() {
        ContextCompat.startForegroundService(context, Intent(context, RayfishVpnService::class.java))
        vpnOn = true
        pendingVpn = true
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) startService() else onToast("VPN permission denied")
    }
    fun toggle(on: Boolean) {
        if (on) {
            val prep = VpnService.prepare(context)
            if (prep != null) consent.launch(prep) else startService()
        } else {
            context.startService(Intent(context, RayfishVpnService::class.java).apply { action = RayfishVpnService.ACTION_STOP })
            vpnOn = false
            pendingVpn = false
        }
    }

    val nets = status?.networks ?: emptyList()
    val online = nets.sumOf { n -> n.peers.count { it.online } }
    val banner = when {
        starting -> "Starting"
        vpnOn -> "Connected · ${nets.size} network${if (nets.size == 1) "" else "s"}"
        else -> "Disconnected"
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BrandHeader()
        StatusEyebrow(connected = vpnOn && !starting, text = banner)
        ToggleCard(
            title = "Tunnel",
            subtitle = if (vpnOn) "running · this device ${status?.ipv4.orEmpty()}" else "stopped",
            checked = vpnOn, onCheckedChange = { toggle(it) },
        )
        SectionCard {
            SectionLabel("This device")
            KeyValueRow("IPv4", status?.ipv4?.ifEmpty { "-" } ?: "-")
            KeyValueRow("IPv6", status?.ipv6?.ifEmpty { "-" } ?: "-")
            KeyValueRow("Networks", "${nets.size} · $online peers online")
        }
    }
}

@androidx.compose.ui.tooling.preview.Preview(backgroundColor = 0xFF18181B, showBackground = true)
@Composable
private fun HomePreview() {
    xyz.rayfish.android.ui.theme.RayfishTheme {
        HomeScreen(
            status = Status(true, "7f3ac2e1", "100.88.0.3", "fd00::7f3a", emptyList(), emptyList()),
            starting = false, onToast = {},
        )
    }
}
