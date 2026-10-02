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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.NetworkDetail
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.isActive
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*

@Composable
fun NetworkDetailScreen(
    detail: NetworkDetail, onBack: () -> Unit, onToast: (String) -> Unit,
    onChanged: () -> Unit, onLeft: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirmLeave by rememberSaveable { mutableStateOf(false) }
    var inviteCode by remember { mutableStateOf<String?>(null) }
    var editing by rememberSaveable { mutableStateOf(false) }
    var hostnameInput by rememberSaveable { mutableStateOf("") }
    var firewall by remember { mutableStateOf<uniffi.ray_mobile.FirewallStateInfo?>(null) }
    var showAddRule by rememberSaveable { mutableStateOf(false) }
    suspend fun reloadFirewall() {
        firewall = try { withContext(Dispatchers.IO) { NodeHolder.get(context).firewallShow() } } catch (t: Throwable) { firewall }
    }
    LaunchedEffect(detail.name) {
        firewall = try { withContext(Dispatchers.IO) { NodeHolder.get(context).firewallShow() } }
        catch (t: Throwable) { null }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.cd_back), tint = Rf.Muted) }
            Text(detail.name, fontFamily = Chakra, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Rf.Heading)
            Spacer(Modifier.weight(1f))
            OverflowMenu(listOf(
                MenuItem(stringResource(R.string.menu_invite)) {
                    scope.launch {
                        try { inviteCode = withContext(Dispatchers.IO) { NodeHolder.get(context).invite(detail.name) } }
                        catch (t: Throwable) { onToast(context.getString(R.string.error_invite_failed, t.message.orEmpty())) }
                    }
                },
                MenuItem(stringResource(R.string.menu_leave_network), destructive = true) { confirmLeave = true },
            ))
        }
        SectionCard {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.label_hostname), fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading)
                TextButton(onClick = { hostnameInput = detail.hostname; editing = true }) {
                    val hostnameShown = detail.hostname.ifEmpty { stringResource(R.string.action_set) }
                    Text(stringResource(R.string.hostname_edit, hostnameShown), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400)
                }
            }
            val addr = detail.hostname.takeIf { it.isNotEmpty() }?.let { "$it.${detail.name}.ray" }
            if (addr != null) KeyValueRow(stringResource(R.string.label_your_address), addr, onClick = { copyToClipboard(context, context.getString(R.string.clipboard_address), addr); onToast(context.getString(R.string.toast_copied, addr)) })
            KeyValueRow(stringResource(R.string.label_role), if (detail.isCoordinator) stringResource(R.string.role_coordinator) else stringResource(R.string.role_member))
            // An unregistered network still opens, because its saved roster is
            // worth seeing. Say plainly that it carries no traffic, or the peer
            // list below reads as live.
            when (detail.state) {
                NetworkConnState.CONNECTING ->
                    KeyValueRow(stringResource(R.string.label_status), stringResource(R.string.status_connecting_ellipsis))
                NetworkConnState.NOT_CONNECTED ->
                    KeyValueRow(stringResource(R.string.label_status), detail.reason ?: stringResource(R.string.status_not_connected))
                NetworkConnState.CONNECTED -> {}
            }
        }
        SectionCard {
            val online = detail.peers.count { it.isActive }
            SectionLabel(pluralStringResource(R.plurals.peers_section, online, online))
            if (detail.peers.isEmpty()) Text(stringResource(R.string.no_peers_yet), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Faint)
            detail.peers.forEach { p ->
                val domain = p.hostname.takeIf { it.isNotEmpty() }?.let { "$it.${detail.name}.ray" }
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(6.dp))
                    .clickable(enabled = domain != null) {
                        if (domain != null && copyToClipboard(context, context.getString(R.string.clipboard_address), domain)) {
                            onToast(context.getString(R.string.toast_copied, domain))
                        }
                    }
                    .padding(top = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(if (p.isActive) Rf.Emerald else Rf.Faint))
                    Spacer(Modifier.width(8.dp))
                    Text(p.hostname.ifEmpty { p.nodeId.take(8) }, fontFamily = Chakra, fontSize = 16.sp, color = Rf.Body, modifier = Modifier.weight(1f))
                    Spacer(Modifier.weight(1f))
                    Text(p.nodeId.take(8),
                        fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Faint)
                }
            }
        }
        SendFilesButton(enabled = detail.peers.isNotEmpty(), onToast = onToast, modifier = Modifier.fillMaxWidth())
        firewall?.let { fw ->
            SectionCard {
                SectionLabel(stringResource(R.string.label_firewall))
                Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.label_inbound_default), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
                    Spacer(Modifier.weight(1f))
                    TextButton(
                        onClick = {
                            val next = if (fw.defaultInbound == "deny") "allow" else "deny"
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetDefaultInbound(next) }
                                    reloadFirewall(); onToast(context.getString(R.string.toast_inbound_default, next))
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_failed, t.message.orEmpty())) }
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) { Text(stringResource(R.string.fw_toggle_edit, fw.defaultInbound), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400) }
                }
                KeyValueRow(stringResource(R.string.label_outbound_default), fw.defaultOutbound)
                if (fw.rules.none { it.direction == "in" }) {
                    Text(stringResource(R.string.no_inbound_rules), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Faint,
                        modifier = Modifier.padding(top = 6.dp))
                }
                fw.rules.forEachIndexed { globalIndex, r ->
                    if (r.direction != "in") return@forEachIndexed
                    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        // `allow`/`deny` and the protocol stay in the daemon's
                        // own vocabulary, in every language: they are the words
                        // `ray firewall` prints and the ones written back over
                        // IPC, so translating half of a rule row would leave it
                        // matching neither.
                        Text(
                            if (r.port != "*") stringResource(R.string.fw_rule_with_port, r.action, r.protocol, r.port)
                            else stringResource(R.string.fw_rule_any_port, r.action, r.protocol),
                            fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Body)
                        Spacer(Modifier.weight(1f))
                        // The daemon renders a rule's peer as a short id; name it
                        // when one of this network's peers carries that prefix.
                        val named = detail.peers.firstOrNull { it.nodeId.startsWith(r.peer) }
                            ?.hostname?.takeIf { it.isNotEmpty() }
                        val peerName = if (r.peer == "any") stringResource(R.string.fw_any_peer) else named ?: r.peer
                        Text(peerName, fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Faint)
                        Spacer(Modifier.width(8.dp))
                        TextButton(onClick = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallRemove(globalIndex.toUInt()) }
                                    reloadFirewall(); onToast(context.getString(R.string.toast_rule_removed))
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_remove_failed, t.message.orEmpty())) }
                            }
                        }) { Text(stringResource(R.string.action_remove), fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Rose400) }
                    }
                }
                TextButton(onClick = { showAddRule = true }) {
                    Text(stringResource(R.string.allow_inbound_add), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400)
                }
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.leave_title, detail.name), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = { Text(stringResource(R.string.leave_body),
                fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    scope.launch {
                        try { withContext(Dispatchers.IO) { NodeHolder.get(context).leave(detail.name) }; onToast(context.getString(R.string.toast_left, detail.name)); onLeft() }
                        catch (t: Throwable) { onToast(context.getString(R.string.error_leave_failed, t.message.orEmpty())) }
                    }
                }) { Text(stringResource(R.string.action_leave), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (editing) {
        AlertDialog(
            onDismissRequest = { editing = false },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.hostname_on, detail.name), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = { RayfishTextField(hostnameInput, { hostnameInput = it }, stringResource(R.string.hint_hostname)) },
            confirmButton = {
                TextButton(onClick = {
                    val h = hostnameInput.trim()
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { NodeHolder.get(context).setHostname(detail.name, h) }
                            onToast(context.getString(R.string.toast_hostname_set)); onChanged(); editing = false
                        } catch (t: Throwable) { onToast(context.getString(R.string.error_invalid_hostname, t.message.orEmpty())) }
                    }
                }) { Text(stringResource(R.string.action_save), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (showAddRule) {
        var proto by rememberSaveable { mutableStateOf("tcp") }
        var port by rememberSaveable { mutableStateOf("") }
        var peerId by rememberSaveable { mutableStateOf<String?>(null) }
        // Label shown in the dropdown -> what firewallAdd matches on. The node id
        // is the unambiguous form: a peer may have no hostname set, and the
        // daemon resolves a full endpoint id for offline members too.
        val anyPeer = stringResource(R.string.fw_any_peer)
        val peerChoices = remember(detail.peers, anyPeer) {
            listOf(anyPeer to null as String?) + detail.peers.map { p ->
                "${p.hostname.ifEmpty { p.nodeId.take(8) }} · ${p.nodeId.take(4)}" to p.nodeId
            }
        }
        val peerLabel = peerChoices.firstOrNull { it.second == peerId }?.first ?: peerId ?: anyPeer
        AlertDialog(
            onDismissRequest = { showAddRule = false },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.allow_inbound), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishDropdown(peerLabel, peerChoices.map { it.first }, { label ->
                        peerId = peerChoices.firstOrNull { it.first == label }?.second
                    }, stringResource(R.string.fw_peer))
                    RayfishDropdown(proto, listOf("tcp", "udp", "icmp", "any"), { proto = it }, stringResource(R.string.fw_protocol))
                    RayfishTextField(port, { port = it.trim() }, stringResource(R.string.hint_port))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val peer = peerId
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                NodeHolder.get(context).firewallAdd(
                                    "in", "allow", proto,
                                    port.ifBlank { null }, peer, detail.name,
                                )
                            }
                            reloadFirewall(); onToast(context.getString(R.string.toast_rule_added)); showAddRule = false
                        } catch (t: Throwable) { onToast(context.getString(R.string.error_add_failed, t.message.orEmpty())) }
                    }
                }) { Text(stringResource(R.string.action_add_rule), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { showAddRule = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    inviteCode?.let { code -> QrCodeSheet(stringResource(R.string.invite_sheet_title), code, context) { inviteCode = null } }
}
