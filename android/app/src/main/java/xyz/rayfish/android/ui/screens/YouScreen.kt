package xyz.rayfish.android.ui.screens

import android.content.Intent
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
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.Telemetry
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.qr.rememberQrScanner
import xyz.rayfish.android.ui.theme.*

@Composable
fun YouScreen(status: Status?, onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var editing by remember { mutableStateOf(false) }
    var hostnameInput by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        deviceName = withContext(Dispatchers.IO) {
            runCatching { NodeHolder.get(context).defaultHostname() }.getOrDefault("")
        }
    }
    var pairingTicket by remember { mutableStateOf<String?>(null) }
    var paired by remember { mutableStateOf(false) }
    var confirmUnpair by remember { mutableStateOf(false) }
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
                Text("Device name", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                TextButton(onClick = { hostnameInput = deviceName; editing = true }) {
                    Text(deviceName.ifEmpty { "set" } + " ✎", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                }
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
                Spacer(Modifier.height(10.dp))
                OutlinePillButton("Unpair this device", onClick = { confirmUnpair = true }, modifier = Modifier.fillMaxWidth())
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
        var stayOnline by remember { mutableStateOf(NodeHolder.isStayOnline(context)) }
        ToggleCard(
            title = "Keep files working when the VPN is off",
            subtitle = if (stayOnline) {
                "on · stays online in the background, so you can run another VPN and still send and receive"
            } else {
                "off · turning the VPN off takes this device offline"
            },
            checked = stayOnline,
            onCheckedChange = { on ->
                stayOnline = on
                NodeHolder.setStayOnline(context, on)
                // If the VPN is actually running (status.running, the real data-plane
                // state, not the persisted isEnabled intent), leave it alone in either
                // direction: this only changes what happens at the next teardown.
                // Otherwise drive the service now, since with the VPN off nothing else
                // reacts to this pref: RayfishApp's launch restore is the only other
                // place that starts the service from these prefs, and that only runs
                // once at launch.
                if (status?.running != true) {
                    if (on) {
                        // Bring the control plane up only, never a tunnel: a plain
                        // intent would land in startTunnel() and try to grab the
                        // single VpnService slot (and pop the consent dialog),
                        // which is exactly what this toggle exists to avoid when
                        // another VPN (Tailscale) is meant to hold that slot.
                        // ACTION_STANDBY routes straight to enterStandby().
                        ContextCompat.startForegroundService(
                            context,
                            Intent(context, RayfishVpnService::class.java).apply {
                                action = RayfishVpnService.ACTION_STANDBY
                            },
                        )
                    } else {
                        // Already in standby (service running, control plane up,
                        // VPN off) and the user just asked to stop keeping it
                        // online: take the node fully offline. The service reads
                        // the now-false pref and does the full offline teardown,
                        // including stopSelf.
                        context.startService(
                            Intent(context, RayfishVpnService::class.java).apply {
                                action = RayfishVpnService.ACTION_STOP
                            },
                        )
                    }
                }
            },
        )
        var autoAcceptOwn by remember { mutableStateOf(NodeHolder.isAutoAcceptOwnDevices(context)) }
        ToggleCard(
            title = "Auto-accept from my devices",
            subtitle = if (autoAcceptOwn) "on · files from your paired devices save to Downloads" else "off · accept them manually",
            checked = autoAcceptOwn,
            onCheckedChange = { on ->
                autoAcceptOwn = on
                NodeHolder.setAutoAcceptOwnDevices(context, on)
            },
        )
        var crashReporting by remember { mutableStateOf(NodeHolder.isCrashReportingEnabled(context)) }
        ToggleCard(
            title = "Crash reporting",
            subtitle = if (crashReporting) "on · diagnostics" else "off",
            checked = crashReporting,
            onCheckedChange = { on ->
                crashReporting = on
                NodeHolder.setCrashReportingEnabled(context, on)
                if (on) Telemetry.enable(context) else Telemetry.disable()
            },
        )
        if (crashReporting) {
            PillButton("Send diagnostics", onClick = {
                scope.launch {
                    val id = withContext(Dispatchers.IO) {
                        runCatching { Telemetry.sendDiagnostics(context) }.getOrNull()
                    }
                    onToast(if (id != null) "Diagnostics sent" else "Diagnostics unavailable")
                }
            }, modifier = Modifier.fillMaxWidth())
        }
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("About", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                Text("v$version", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Muted)
            }
        }
    }

    if (editing) {
        AlertDialog(
            onDismissRequest = { editing = false },
            containerColor = Rf.Sheet,
            title = { Text("Device name", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
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
                                node.setDefaultHostname(h)
                                nets.forEach { node.setHostname(it.name, h) }
                            }
                            deviceName = h
                            onToast("Device name set"); onChanged(); editing = false
                        } catch (t: Throwable) { onToast("Invalid name: ${t.message}") }
                    }
                }) { Text("Save", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (confirmUnpair) {
        AlertDialog(
            onDismissRequest = { confirmUnpair = false },
            containerColor = Rf.Sheet,
            title = { Text("Unpair this device?", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Text("This device leaves all your networks and deletes its pairing certificate. Peers disconnect from it right away. Re-pair from your primary device to rejoin.",
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Body)
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmUnpair = false
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { NodeHolder.get(context).unpair() }
                            paired = false
                            onToast("Unpaired this device"); onChanged()
                        } catch (t: Throwable) { onToast("Unpair failed: ${t.message}") }
                    }
                }) { Text("Unpair", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { confirmUnpair = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    pairingTicket?.let { t -> QrCodeSheet("Show this to your other device", t, context, onToast) { pairingTicket = null } }
}
