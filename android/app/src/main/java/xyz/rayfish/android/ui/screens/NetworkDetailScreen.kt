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
import androidx.compose.ui.graphics.Color
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
import xyz.rayfish.android.ui.userMessage

@Composable
fun NetworkDetailScreen(
    detail: NetworkDetail, onBack: () -> Unit, onToast: (String) -> Unit,
    onChanged: () -> Unit, onLeft: () -> Unit,
    onOpenGeneralFirewall: () -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirmLeave by rememberSaveable { mutableStateOf(false) }
    var inviteCode by remember { mutableStateOf<String?>(null) }
    var sendingInvite by rememberSaveable { mutableStateOf(false) }
    var editing by rememberSaveable { mutableStateOf(false) }
    var hostnameInput by rememberSaveable { mutableStateOf("") }
    var firewall by remember { mutableStateOf<uniffi.ray_mobile.FirewallStateInfo?>(null) }
    var showAddRule by rememberSaveable { mutableStateOf(false) }
    var addRulePeerId by rememberSaveable { mutableStateOf<String?>(null) }
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
            OverflowMenu(listOfNotNull(
                MenuItem(stringResource(R.string.menu_invite)) {
                    scope.launch {
                        try { inviteCode = withContext(Dispatchers.IO) { NodeHolder.get(context).invite(detail.name) } }
                        catch (t: Throwable) { onToast(context.getString(R.string.error_invite_failed, t.userMessage)) }
                    }
                },
                if (detail.isCoordinator) MenuItem(stringResource(R.string.menu_send_invite)) { sendingInvite = true } else null,
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
                    Text(p.nodeId.take(8),
                        fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Faint)
                    Spacer(Modifier.width(4.dp))
                    TextButton(
                        onClick = { addRulePeerId = p.nodeId; showAddRule = true },
                        contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp),
                    ) {
                        Text(stringResource(R.string.fw_peer_add_rule), fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Rose400)
                    }
                }
            }
        }
        SendFilesButton(enabled = detail.peers.isNotEmpty(), onToast = onToast, modifier = Modifier.fillMaxWidth())
        firewall?.let { fw ->
            val netFw = fw.networks.firstOrNull { it.network == detail.name }
            val pendingRules = netFw?.pendingRules.orEmpty()
            val pendingCount = if (pendingRules.isNotEmpty()) pendingRules.size.toUInt() else detail.pendingSuggestions
            val autoAccept = netFw?.autoAccept ?: detail.autoAcceptFirewall
            val networkRules = fw.rules.withIndex().filter { (_, r) -> r.network == detail.name }

            SectionCard {
                SectionLabel(stringResource(R.string.label_firewall))
                if (fw.disabled) {
                    Text(
                        stringResource(R.string.fw_paused_title),
                        fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Amber,
                        modifier = Modifier.padding(bottom = 4.dp),
                    )
                }
                if (pendingRules.isNotEmpty() || pendingCount > 0u) {
                    PendingSuggestionsBlock(
                        pendingRules = pendingRules,
                        pendingCount = pendingCount,
                        peers = detail.peers,
                        onAccept = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallAcceptSuggestions(detail.name) }
                                    reloadFirewall(); onChanged(); onToast(context.getString(R.string.toast_suggestions_accepted))
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_failed, t.userMessage)) }
                            }
                        },
                        onDismiss = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallDenySuggestions(detail.name) }
                                    reloadFirewall(); onChanged(); onToast(context.getString(R.string.toast_suggestions_dismissed))
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_failed, t.userMessage)) }
                            }
                        },
                    )
                }
                if (networkRules.isEmpty()) {
                    Text(
                        stringResource(R.string.no_inbound_rules),
                        fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Faint,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
                networkRules.forEach { (globalIndex, r) ->
                    FirewallRuleRow(
                        rule = r,
                        peers = detail.peers,
                        onRemove = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallRemove(globalIndex.toUInt()) }
                                    reloadFirewall(); onToast(context.getString(R.string.toast_rule_removed))
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_remove_failed, t.userMessage)) }
                            }
                        },
                    )
                }
                TextButton(onClick = { addRulePeerId = null; showAddRule = true }) {
                    Text(stringResource(R.string.allow_inbound_add), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400)
                }
                Row(
                    Modifier.fillMaxWidth().padding(top = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        Text(
                            stringResource(R.string.fw_auto_accept_title),
                            fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading,
                        )
                        Text(
                            stringResource(R.string.fw_auto_accept_subtitle),
                            fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Muted,
                            modifier = Modifier.padding(top = 2.dp),
                        )
                    }
                    Switch(
                        checked = autoAccept,
                        onCheckedChange = { enabled ->
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).setNetworkFirewallAutoAccept(detail.name, enabled) }
                                    reloadFirewall(); onChanged()
                                } catch (t: Throwable) { onToast(context.getString(R.string.error_failed, t.userMessage)) }
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White, checkedTrackColor = Rf.Emerald,
                            uncheckedThumbColor = Color.White, uncheckedTrackColor = Rf.Faint,
                            checkedBorderColor = Color.Transparent, uncheckedBorderColor = Color.Transparent,
                        ),
                    )
                }
                Row(
                    Modifier.fillMaxWidth().padding(top = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        stringResource(R.string.fw_general_summary, fw.defaultInbound, fw.defaultOutbound),
                        fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = onOpenGeneralFirewall,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) {
                        Text(stringResource(R.string.fw_open_general), fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Rose400)
                    }
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
                        catch (t: Throwable) { onToast(context.getString(R.string.error_leave_failed, t.userMessage)) }
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
                        } catch (t: Throwable) { onToast(context.getString(R.string.error_invalid_hostname, t.userMessage)) }
                    }
                }) { Text(stringResource(R.string.action_save), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (showAddRule) {
        AddFirewallRuleDialog(
            networks = listOf(detail),
            lockedNetwork = detail.name,
            initialNetwork = detail.name,
            initialPeerId = addRulePeerId,
            onDismiss = { showAddRule = false },
            onAdded = {
                showAddRule = false
                scope.launch { reloadFirewall() }
            },
            onToast = onToast,
        )
    }
    if (sendingInvite) {
        IdentityDialog(
            title = stringResource(R.string.send_invite_title, detail.name),
            body = stringResource(R.string.send_invite_body),
            confirmLabel = stringResource(R.string.action_send),
            onDismiss = { sendingInvite = false },
            onToast = onToast,
        ) { recipient -> NodeHolder.get(context).sendInvite(detail.name, recipient) }
    }
    inviteCode?.let { code -> QrCodeSheet(stringResource(R.string.invite_sheet_title), code, context) { inviteCode = null } }
}
