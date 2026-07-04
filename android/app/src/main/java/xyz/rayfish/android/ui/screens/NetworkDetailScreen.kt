package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.NetworkDetail
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*

@Composable
fun NetworkDetailScreen(
    detail: NetworkDetail, onBack: () -> Unit, onToast: (String) -> Unit,
    onChanged: () -> Unit, onLeft: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirmLeave by remember { mutableStateOf(false) }
    var inviteCode by remember { mutableStateOf<String?>(null) }
    var editing by remember { mutableStateOf(false) }
    var hostnameInput by remember { mutableStateOf("") }
    var firewall by remember { mutableStateOf<uniffi.ray_mobile.FirewallStateInfo?>(null) }
    var showAddRule by remember { mutableStateOf(false) }
    suspend fun reloadFirewall() {
        firewall = try { withContext(Dispatchers.IO) { NodeHolder.get(context).firewallShow() } } catch (t: Throwable) { firewall }
    }
    LaunchedEffect(detail.name) {
        firewall = try { withContext(Dispatchers.IO) { NodeHolder.get(context).firewallShow() } }
        catch (t: Throwable) { null }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Rf.Muted) }
            Text(detail.name, fontFamily = Chakra, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Rf.Heading)
            Spacer(Modifier.weight(1f))
            OverflowMenu(listOf(
                MenuItem("Invite to share") {
                    scope.launch {
                        try { inviteCode = withContext(Dispatchers.IO) { NodeHolder.get(context).invite(detail.name) } }
                        catch (t: Throwable) { onToast("Invite failed: ${t.message}") }
                    }
                },
                MenuItem("Leave network", destructive = true) { confirmLeave = true },
            ))
        }
        SectionCard {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Hostname", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                TextButton(onClick = { hostnameInput = detail.hostname; editing = true }) {
                    Text(detail.hostname.ifEmpty { "set" } + " ✎", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                }
            }
            val addr = "${detail.hostname.ifEmpty { "-" }}.${detail.name}.ray"
            KeyValueRow("Your address", addr, onClick = { copyToClipboard(context, "address", addr); onToast("Copied $addr") })
            val ip4 = detail.ipv4.takeIf { it.isNotEmpty() }
            KeyValueRow("IPv4", ip4 ?: "-", onClick = ip4?.let { v -> { copyToClipboard(context, "IPv4", v); onToast("Copied $v") } })
            KeyValueRow("Role", if (detail.isCoordinator) "coordinator" else "member")
        }
        SectionCard {
            SectionLabel("Peers · ${detail.peers.count { it.online }} online")
            if (detail.peers.isEmpty()) Text("No peers yet", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint)
            detail.peers.forEach { p ->
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(6.dp))
                    .clickable { copyToClipboard(context, p.hostname.ifEmpty { "peer" }, p.ipv4); onToast("Copied ${p.ipv4}") }
                    .padding(top = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(if (p.online) Rf.Emerald else Rf.Faint))
                    Spacer(Modifier.width(8.dp))
                    Text(p.ipv4, fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Body)
                    Spacer(Modifier.weight(1f))
                    Text("${p.hostname.ifEmpty { "?" }} · ${p.nodeId.take(4)}", fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Faint)
                }
            }
        }
        firewall?.let { fw ->
            SectionCard {
                SectionLabel("Firewall")
                Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("Inbound default", fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
                    Spacer(Modifier.weight(1f))
                    TextButton(
                        onClick = {
                            val next = if (fw.defaultInbound == "deny") "allow" else "deny"
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetDefaultInbound(next) }
                                    reloadFirewall(); onToast("Inbound default: $next")
                                } catch (t: Throwable) { onToast("Failed: ${t.message}") }
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) { Text("${fw.defaultInbound} ✎", fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Rose400) }
                }
                KeyValueRow("Outbound default", fw.defaultOutbound)
                if (fw.rules.none { it.direction == "in" }) {
                    Text("No inbound rules", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint,
                        modifier = Modifier.padding(top = 6.dp))
                }
                fw.rules.forEachIndexed { globalIndex, r ->
                    if (r.direction != "in") return@forEachIndexed
                    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("${r.action} ${r.protocol}${if (r.port != "*") ":" + r.port else ""}",
                            fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Body)
                        Spacer(Modifier.weight(1f))
                        Text(r.peer, fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Faint)
                        Spacer(Modifier.width(8.dp))
                        TextButton(onClick = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallRemove(globalIndex.toUInt()) }
                                    reloadFirewall(); onToast("Rule removed")
                                } catch (t: Throwable) { onToast("Remove failed: ${t.message}") }
                            }
                        }) { Text("remove", fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Rose400) }
                    }
                }
                TextButton(onClick = { showAddRule = true }) {
                    Text("+ Allow inbound", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                }
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            containerColor = Rf.Sheet,
            title = { Text("Leave ${detail.name}?", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = { Text("You'll lose your address and stop reaching its peers. You can rejoin later with an invite.",
                fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    scope.launch {
                        try { withContext(Dispatchers.IO) { NodeHolder.get(context).leave(detail.name) }; onToast("Left ${detail.name}"); onLeft() }
                        catch (t: Throwable) { onToast("Leave failed: ${t.message}") }
                    }
                }) { Text("Leave", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (editing) {
        AlertDialog(
            onDismissRequest = { editing = false },
            containerColor = Rf.Sheet,
            title = { Text("Hostname on ${detail.name}", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = { RayfishTextField(hostnameInput, { hostnameInput = it }, "lowercase, 1-63 chars") },
            confirmButton = {
                TextButton(onClick = {
                    val h = hostnameInput.trim()
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { NodeHolder.get(context).setHostname(detail.name, h) }
                            onToast("Hostname set"); onChanged(); editing = false
                        } catch (t: Throwable) { onToast("Invalid hostname: ${t.message}") }
                    }
                }) { Text("Save", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (showAddRule) {
        var proto by remember { mutableStateOf("tcp") }
        var port by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showAddRule = false },
            containerColor = Rf.Sheet,
            title = { Text("Allow inbound", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishDropdown(proto, listOf("tcp", "udp", "icmp", "any"), { proto = it }, "protocol")
                    RayfishTextField(port, { port = it.trim() }, "port (blank for any), e.g. 22")
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                NodeHolder.get(context).firewallAdd(
                                    "in", "allow", proto,
                                    port.ifBlank { null }, null, detail.name,
                                )
                            }
                            reloadFirewall(); onToast("Rule added"); showAddRule = false
                        } catch (t: Throwable) { onToast("Add failed: ${t.message}") }
                    }
                }) { Text("Add", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { showAddRule = false }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    inviteCode?.let { code -> QrCodeSheet("Invite to share", code, context, onToast) { inviteCode = null } }
}
