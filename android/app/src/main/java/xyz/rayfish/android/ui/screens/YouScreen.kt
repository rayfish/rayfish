package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.Telemetry
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.qr.rememberQrScanner
import xyz.rayfish.android.ui.theme.*

@Composable
fun YouScreen(status: Status?, onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val firstNet = status?.networks?.firstOrNull()
    var editing by remember { mutableStateOf(false) }
    var hostnameInput by remember { mutableStateOf("") }
    var pairingTicket by remember { mutableStateOf<String?>(null) }
    var paired by remember { mutableStateOf(false) }
    // A device that already holds a cert cannot pair again (it must not mint new
    // certs). Refresh whenever status changes so the card flips right after a pair.
    LaunchedEffect(status?.nodeId) {
        paired = withContext(Dispatchers.IO) { runCatching { NodeHolder.get(context).isPaired() }.getOrDefault(false) }
    }
    val version = remember {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "-"
    }

    val scan = rememberQrScanner { result ->
        if (result != null) scope.launch {
            try {
                val action = withContext(Dispatchers.IO) { NodeHolder.get(context).submitCode(result.trim()) }
                onToast(when (action) {
                    is uniffi.ray_mobile.LinkAction.Joined ->
                        if (action.v1.pending) "Join requested for ${action.v1.name} - waiting for approval"
                        else "Joined ${action.v1.name}"
                    is uniffi.ray_mobile.LinkAction.Paired -> "Device paired"
                })
                onChanged()
            } catch (t: Throwable) { onToast("Failed: ${t.message}") }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BrandHeader(title = "You")
        SectionCard {
            SectionLabel("This device")
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Hostname", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                if (firstNet != null) TextButton(onClick = { hostnameInput = firstNet.hostname; editing = true }) {
                    Text(firstNet.hostname.ifEmpty { "set" } + " ✎", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                } else Text("join a network first", fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint)
            }
            val nodeId = status?.nodeId?.takeIf { it.isNotEmpty() }
            val ip4 = status?.ipv4?.takeIf { it.isNotEmpty() }
            val ip6 = status?.ipv6?.takeIf { it.isNotEmpty() }
            KeyValueRow("Node ID", nodeId?.let { if (it.length > 12) "${it.take(6)}…${it.takeLast(4)}" else it } ?: "-",
                onClick = nodeId?.let { v -> { copyToClipboard(context, "Node ID", v); onToast("Copied node ID") } })
            KeyValueRow("IPv4", ip4 ?: "-", onClick = ip4?.let { v -> { copyToClipboard(context, "IPv4", v); onToast("Copied $v") } })
            KeyValueRow("IPv6", ip6 ?: "-", onClick = ip6?.let { v -> { copyToClipboard(context, "IPv6", v); onToast("Copied $v") } })
        }
        SectionCard {
            SectionLabel("Pairing")
            val running = status?.running == true
            if (!running) {
                Text("Start the tunnel to pair another device.",
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
            } else if (paired) {
                Text("This device is paired. Add new devices from your primary device.",
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
            } else {
                Text("Pair another of your devices: show it a code, or scan the code it shows.",
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PillButton("Show my code", onClick = {
                        scope.launch {
                            try { pairingTicket = withContext(Dispatchers.IO) { NodeHolder.get(context).startPairing() } }
                            catch (t: Throwable) { onToast("Pairing failed: ${t.message}") }
                        }
                    }, modifier = Modifier.weight(1f))
                    OutlinePillButton("Scan a code", onClick = scan, modifier = Modifier.weight(1f))
                }
            }
        }
        var crashReporting by remember { mutableStateOf(NodeHolder.isCrashReportingEnabled(context)) }
        ToggleCard(
            title = "Crash reporting",
            subtitle = if (crashReporting) "on · anonymous diagnostics" else "off",
            checked = crashReporting,
            onCheckedChange = { on ->
                crashReporting = on
                NodeHolder.setCrashReportingEnabled(context, on)
                if (on) Telemetry.enable(context) else Telemetry.disable()
            },
        )
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("About", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                Text("v$version", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Muted)
            }
        }
    }

    if (editing && firstNet != null) {
        AlertDialog(
            onDismissRequest = { editing = false },
            containerColor = Rf.Sheet,
            title = { Text("Hostname", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishTextField(hostnameInput, { hostnameInput = it }, "lowercase, 1-63 chars")
                    Text("Applies to all your networks.", fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val h = hostnameInput.trim()
                    val nets = status?.networks.orEmpty()
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                val node = NodeHolder.get(context)
                                nets.forEach { node.setHostname(it.name, h) }
                            }
                            onToast("Hostname set"); onChanged(); editing = false
                        } catch (t: Throwable) { onToast("Invalid hostname: ${t.message}") }
                    }
                }) { Text("Save", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    pairingTicket?.let { t -> QrCodeSheet("Show this to your other device", t, context, onToast) { pairingTicket = null } }
}
