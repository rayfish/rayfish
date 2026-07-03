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
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.qr.rememberQrScanner
import xyz.rayfish.android.ui.theme.*

@Composable
fun YouScreen(status: Status?, onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val firstNet = status?.networks?.firstOrNull()
    var editing by remember { mutableStateOf(false) }
    var hostnameInput by remember(firstNet?.hostname) { mutableStateOf(firstNet?.hostname ?: "") }
    var pairingTicket by remember { mutableStateOf<String?>(null) }
    val version = remember {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "-"
    }

    val scan = rememberQrScanner { result ->
        if (result != null) scope.launch {
            try { withContext(Dispatchers.IO) { NodeHolder.get(context).pair(result) }; onToast("Paired"); onChanged() }
            catch (t: Throwable) { onToast("Pair failed: ${t.message}") }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BrandHeader(title = "You")
        SectionCard {
            SectionLabel("This device")
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Hostname", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                if (firstNet != null) TextButton(onClick = { editing = true }) {
                    Text(firstNet.hostname.ifEmpty { "set" } + " ✎", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                } else Text("join a network first", fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint)
            }
            KeyValueRow("Node ID", status?.nodeId?.let { if (it.length > 12) "${it.take(6)}…${it.takeLast(4)}" else it } ?: "-")
            KeyValueRow("IPv4", status?.ipv4?.ifEmpty { "-" } ?: "-")
            KeyValueRow("IPv6", status?.ipv6?.ifEmpty { "-" } ?: "-")
        }
        SectionCard {
            SectionLabel("Pairing")
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
            title = { Text("Hostname on ${firstNet.name}", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = { RayfishTextField(hostnameInput, { hostnameInput = it }, "lowercase, 1-63 chars") },
            confirmButton = {
                TextButton(onClick = {
                    val h = hostnameInput.trim()
                    editing = false
                    scope.launch {
                        try { withContext(Dispatchers.IO) { NodeHolder.get(context).setHostname(firstNet.name, h) }; onToast("Hostname set"); onChanged() }
                        catch (t: Throwable) { onToast("Invalid hostname: ${t.message}") }
                    }
                }) { Text("Save", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    pairingTicket?.let { t -> QrCodeSheet("Show this to your other device", t, context, onToast) { pairingTicket = null } }
}
