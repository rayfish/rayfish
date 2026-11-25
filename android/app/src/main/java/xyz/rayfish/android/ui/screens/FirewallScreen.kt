package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import uniffi.ray_mobile.FirewallRuleInfo
import uniffi.ray_mobile.FirewallStateInfo
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.PeerInfo
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*
import xyz.rayfish.android.ui.userMessage

/** True when a firewall rule applies across all networks rather than a single named network. */
internal fun FirewallRuleInfo.isGeneralRule(knownNetworks: Set<String>): Boolean =
    network.isEmpty() || network == "*" || network == "any" ||
        (knownNetworks.isNotEmpty() && network !in knownNetworks)

/** Resolve a rule's peer identifier against known network peers for display. */
@Composable
internal fun resolveRulePeerLabel(peer: String, peers: List<PeerInfo>): String {
    if (peer.isEmpty() || peer == "*" || peer == "any") {
        return stringResource(R.string.fw_any_peer)
    }
    val named = peers.firstOrNull { it.nodeId.startsWith(peer) || it.hostname == peer }
        ?.hostname?.takeIf { it.isNotEmpty() }
    return named ?: peer
}

@Composable
fun FirewallScreen(
    status: Status?,
    onBack: () -> Unit,
    onToast: (String) -> Unit,
    onChanged: () -> Unit = {},
    onOpenNetwork: (String) -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var firewall by remember { mutableStateOf<FirewallStateInfo?>(null) }
    var showAddRule by rememberSaveable { mutableStateOf(false) }
    var confirmAllowInbound by rememberSaveable { mutableStateOf(false) }
    var confirmDenyOutbound by rememberSaveable { mutableStateOf(false) }

    suspend fun reloadFirewall() {
        firewall = try {
            withContext(Dispatchers.IO) { NodeHolder.get(context).firewallShow() }
        } catch (t: Throwable) {
            firewall
        }
    }

    LaunchedEffect(status?.networks) {
        reloadFirewall()
    }

    val nets = status?.networks.orEmpty()
    val knownNetworkNames = remember(nets) { nets.map { it.name }.toSet() }
    val allPeers = remember(nets) { nets.flatMap { it.peers }.distinctBy { it.nodeId } }

    fun setInboundDefault(next: String) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetDefaultInbound(next) }
                reloadFirewall()
                onChanged()
                onToast(context.getString(R.string.toast_inbound_default, next))
            } catch (t: Throwable) {
                onToast(context.getString(R.string.error_failed, t.userMessage))
            }
        }
    }

    fun setOutboundDefault(next: String) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetDefaultOutbound(next) }
                reloadFirewall()
                onChanged()
                onToast(context.getString(R.string.toast_outbound_default, next))
            } catch (t: Throwable) {
                onToast(context.getString(R.string.error_failed, t.userMessage))
            }
        }
    }

    fun setEnabled(enabled: Boolean) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetEnabled(enabled) }
                reloadFirewall()
                onChanged()
                onToast(context.getString(if (enabled) R.string.toast_fw_enabled else R.string.toast_fw_paused))
            } catch (t: Throwable) {
                onToast(context.getString(R.string.error_failed, t.userMessage))
            }
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.cd_back), tint = Rf.Muted)
            }
            Text(
                stringResource(R.string.label_firewall),
                fontFamily = Chakra, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Rf.Heading,
            )
        }

        firewall?.let { fw ->
            if (fw.disabled) {
                SectionCard {
                    Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(Modifier.weight(1f).padding(end = 12.dp)) {
                            Text(
                                stringResource(R.string.fw_paused_title),
                                fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Amber,
                            )
                            Text(
                                stringResource(R.string.fw_paused_body),
                                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted,
                                modifier = Modifier.padding(top = 3.dp),
                            )
                        }
                        TextButton(onClick = { setEnabled(true) }) {
                            Text(
                                stringResource(R.string.fw_action_resume),
                                fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Amber,
                            )
                        }
                    }
                }
            }

            SectionCard {
                SectionLabel(stringResource(R.string.fw_section_posture))
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        Text(
                            stringResource(R.string.fw_enforce_title),
                            fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading,
                        )
                        Text(
                            stringResource(R.string.fw_enforce_subtitle),
                            fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted,
                            modifier = Modifier.padding(top = 2.dp),
                        )
                    }
                    Switch(
                        checked = !fw.disabled,
                        onCheckedChange = { setEnabled(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White, checkedTrackColor = Rf.Emerald,
                            uncheckedThumbColor = Color.White, uncheckedTrackColor = Rf.Faint,
                            checkedBorderColor = Color.Transparent, uncheckedBorderColor = Color.Transparent,
                        ),
                    )
                }

                Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.label_inbound_default), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
                    Spacer(Modifier.weight(1f))
                    TextButton(
                        onClick = {
                            if (fw.defaultInbound == "deny") {
                                confirmAllowInbound = true
                            } else {
                                setInboundDefault("deny")
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) {
                        Text(
                            stringResource(R.string.fw_toggle_edit, fw.defaultInbound),
                            fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400,
                        )
                    }
                }

                Row(Modifier.fillMaxWidth().padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.label_outbound_default), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
                    Spacer(Modifier.weight(1f))
                    TextButton(
                        onClick = {
                            if (fw.defaultOutbound == "allow") {
                                confirmDenyOutbound = true
                            } else {
                                setOutboundDefault("allow")
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) {
                        Text(
                            stringResource(R.string.fw_toggle_edit, fw.defaultOutbound),
                            fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400,
                        )
                    }
                }

                Row(
                    Modifier.fillMaxWidth().padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f).padding(end = 12.dp)) {
                        Text(
                            stringResource(R.string.fw_reject_title),
                            fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading,
                        )
                        Text(
                            stringResource(R.string.fw_reject_subtitle),
                            fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted,
                            modifier = Modifier.padding(top = 2.dp),
                        )
                    }
                    Switch(
                        checked = fw.reject,
                        onCheckedChange = { reject ->
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallSetReject(reject) }
                                    reloadFirewall()
                                    onChanged()
                                } catch (t: Throwable) {
                                    onToast(context.getString(R.string.error_failed, t.userMessage))
                                }
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White, checkedTrackColor = Rf.Emerald,
                            uncheckedThumbColor = Color.White, uncheckedTrackColor = Rf.Faint,
                            checkedBorderColor = Color.Transparent, uncheckedBorderColor = Color.Transparent,
                        ),
                    )
                }
            }

            SectionCard {
                SectionLabel(stringResource(R.string.fw_section_general_rules))
                Text(
                    stringResource(R.string.fw_general_rules_hint),
                    fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted,
                )
                val generalRules = fw.rules.withIndex().filter { (_, r) -> r.isGeneralRule(knownNetworkNames) }
                if (generalRules.isEmpty()) {
                    Text(
                        stringResource(R.string.fw_no_general_rules),
                        fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Faint,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
                generalRules.forEach { (globalIndex, r) ->
                    val netTag = r.network.takeIf { it.isNotEmpty() && it != "*" && it != "any" }
                    FirewallRuleRow(
                        rule = r,
                        peers = allPeers,
                        networkBadge = netTag ?: stringResource(R.string.fw_all_networks),
                        onRemove = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallRemove(globalIndex.toUInt()) }
                                    reloadFirewall()
                                    onChanged()
                                    onToast(context.getString(R.string.toast_rule_removed))
                                } catch (t: Throwable) {
                                    onToast(context.getString(R.string.error_remove_failed, t.userMessage))
                                }
                            }
                        },
                    )
                }
                TextButton(onClick = { showAddRule = true }) {
                    Text(stringResource(R.string.fw_add_general_rule), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Rose400)
                }
            }

            val pendingByNetwork = fw.networks.filter { it.pendingRules.isNotEmpty() }
            pendingByNetwork.forEach { netFw ->
                val netPeers = nets.firstOrNull { it.name == netFw.network }?.peers ?: allPeers
                SectionCard {
                    PendingSuggestionsBlock(
                        networkName = netFw.network,
                        pendingRules = netFw.pendingRules,
                        pendingCount = netFw.pendingRules.size.toUInt(),
                        peers = netPeers,
                        onAccept = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallAcceptSuggestions(netFw.network) }
                                    reloadFirewall()
                                    onChanged()
                                    onToast(context.getString(R.string.toast_suggestions_accepted))
                                } catch (t: Throwable) {
                                    onToast(context.getString(R.string.error_failed, t.userMessage))
                                }
                            }
                        },
                        onDismiss = {
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) { NodeHolder.get(context).firewallDenySuggestions(netFw.network) }
                                    reloadFirewall()
                                    onChanged()
                                    onToast(context.getString(R.string.toast_suggestions_dismissed))
                                } catch (t: Throwable) {
                                    onToast(context.getString(R.string.error_failed, t.userMessage))
                                }
                            }
                        },
                    )
                }
            }

            SectionCard {
                SectionLabel(stringResource(R.string.fw_section_network_rules))
                if (nets.isEmpty()) {
                    Text(stringResource(R.string.networks_empty), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
                }
                nets.forEach { net ->
                    val ruleCount = fw.rules.count { it.network == net.name }
                    val netFw = fw.networks.firstOrNull { it.network == net.name }
                    val pendingCount = netFw?.pendingRules?.size?.toUInt()?.takeIf { it > 0u } ?: net.pendingSuggestions
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                            .clickable { onOpenNetwork(net.name) }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(net.name, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading)
                            Text(
                                pluralStringResource(R.plurals.fw_network_rule_count, ruleCount, ruleCount),
                                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted,
                            )
                        }
                        if (pendingCount > 0u) {
                            Text(
                                pluralStringResource(R.plurals.fw_pending_badge, pendingCount.toInt(), pendingCount.toInt()),
                                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Amber,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(Rf.Amber.copy(alpha = 0.14f))
                                    .padding(horizontal = 8.dp, vertical = 3.dp),
                            )
                        }
                    }
                }
            }
        }
    }

    if (confirmAllowInbound) {
        AlertDialog(
            onDismissRequest = { confirmAllowInbound = false },
            containerColor = Rf.Sheet,
            title = {
                Text(
                    stringResource(R.string.fw_confirm_inbound_allow_title),
                    fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading,
                )
            },
            text = {
                Text(
                    stringResource(R.string.fw_confirm_inbound_allow_body),
                    fontFamily = Chakra, fontSize = 14.sp, color = Rf.Body,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmAllowInbound = false
                    setInboundDefault("allow")
                }) {
                    Text(
                        stringResource(R.string.action_continue),
                        color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmAllowInbound = false }) {
                    Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }

    if (confirmDenyOutbound) {
        AlertDialog(
            onDismissRequest = { confirmDenyOutbound = false },
            containerColor = Rf.Sheet,
            title = {
                Text(
                    stringResource(R.string.fw_confirm_outbound_deny_title),
                    fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading,
                )
            },
            text = {
                Text(
                    stringResource(R.string.fw_confirm_outbound_deny_body),
                    fontFamily = Chakra, fontSize = 14.sp, color = Rf.Body,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDenyOutbound = false
                    setOutboundDefault("deny")
                }) {
                    Text(
                        stringResource(R.string.action_continue),
                        color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDenyOutbound = false }) {
                    Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }

    if (showAddRule) {
        AddFirewallRuleDialog(
            networks = nets,
            lockedNetwork = null,
            initialNetwork = null,
            initialPeerId = null,
            onDismiss = { showAddRule = false },
            onAdded = {
                showAddRule = false
                scope.launch {
                    reloadFirewall()
                    onChanged()
                }
            },
            onToast = onToast,
        )
    }
}

@Composable
internal fun PendingSuggestionsBlock(
    networkName: String? = null,
    pendingRules: List<FirewallRuleInfo>,
    pendingCount: UInt,
    peers: List<PeerInfo>,
    onAccept: () -> Unit,
    onDismiss: () -> Unit,
) {
    Column(
        Modifier.fillMaxWidth().padding(top = 6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        val header = if (networkName != null) {
            "${stringResource(R.string.fw_pending_suggestions_title)} · $networkName"
        } else {
            stringResource(R.string.fw_pending_suggestions_title)
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                header,
                fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Amber,
                modifier = Modifier.weight(1f),
            )
            Text(
                pluralStringResource(R.plurals.fw_pending_badge, pendingCount.toInt(), pendingCount.toInt()),
                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Amber,
            )
        }
        pendingRules.forEach { r ->
            val peerName = resolveRulePeerLabel(r.peer, peers)
            val spec = if (r.port.isNotEmpty() && r.port != "*" && r.port != "any") {
                stringResource(R.string.fw_rule_with_port, r.action, r.protocol, r.port)
            } else {
                stringResource(R.string.fw_rule_any_port, r.action, r.protocol)
            }
            Text(
                "${r.direction} $spec · $peerName",
                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Body,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onAccept, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)) {
                Text(
                    stringResource(R.string.fw_accept_suggestions),
                    fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Emerald,
                )
            }
            TextButton(onClick = onDismiss, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)) {
                Text(
                    stringResource(R.string.fw_dismiss_suggestions),
                    fontFamily = Chakra, fontSize = 13.sp, color = Rf.Rose400,
                )
            }
        }
    }
}

@Composable
internal fun FirewallRuleRow(
    rule: FirewallRuleInfo,
    peers: List<PeerInfo>,
    networkBadge: String? = null,
    onRemove: () -> Unit,
) {
    val actionColor = if (rule.action == "allow") Rf.Emerald else Rf.Rose400
    val hasPort = rule.port.isNotEmpty() && rule.port != "*" && rule.port != "any"
    val ruleText = if (hasPort) {
        stringResource(R.string.fw_rule_with_port, rule.action, rule.protocol, rule.port)
    } else {
        stringResource(R.string.fw_rule_any_port, rule.action, rule.protocol)
    }
    val peerName = resolveRulePeerLabel(rule.peer, peers)

    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            rule.direction,
            fontFamily = PlexMono, fontSize = 11.sp, color = actionColor,
            modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(actionColor.copy(alpha = 0.14f))
                .padding(horizontal = 6.dp, vertical = 2.dp),
        )
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(ruleText, fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Body)
            val metaParts = buildList {
                add(peerName)
                if (networkBadge != null) add(networkBadge)
                if (rule.suggestedBy != null && rule.suggestedBy != "ssh") {
                    add(stringResource(R.string.fw_suggested_badge))
                }
            }
            Text(
                metaParts.joinToString(" · "),
                fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Faint,
            )
        }
        Spacer(Modifier.width(8.dp))
        if (rule.suggestedBy == "ssh") {
            Text(
                stringResource(R.string.fw_managed_by_ssh),
                fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint,
            )
        } else {
            TextButton(onClick = onRemove) {
                Text(stringResource(R.string.action_remove), fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Rose400)
            }
        }
    }
}

@Composable
fun AddFirewallRuleDialog(
    networks: List<NetworkDetail>,
    lockedNetwork: String? = null,
    initialNetwork: String? = lockedNetwork,
    initialPeerId: String? = null,
    onDismiss: () -> Unit,
    onAdded: () -> Unit,
    onToast: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var networkScope by rememberSaveable { mutableStateOf(lockedNetwork ?: initialNetwork ?: "") }
    var direction by rememberSaveable { mutableStateOf("in") }
    var action by rememberSaveable { mutableStateOf("allow") }
    var proto by rememberSaveable { mutableStateOf("tcp") }
    var port by rememberSaveable { mutableStateOf("") }
    var peerId by rememberSaveable { mutableStateOf(initialPeerId) }

    val allNetworksLabel = stringResource(R.string.fw_all_networks)
    val scopeChoices = remember(networks, allNetworksLabel) {
        listOf(allNetworksLabel to "") + networks.map { it.name to it.name }
    }
    val scopeLabel = scopeChoices.firstOrNull { it.second == networkScope }?.first
        ?: networkScope.ifEmpty { allNetworksLabel }

    val activePeers = remember(networks, networkScope) {
        val target = networks.firstOrNull { it.name == networkScope }
        (target?.peers ?: networks.flatMap { it.peers }).distinctBy { it.nodeId }
    }
    val anyPeer = stringResource(R.string.fw_any_peer)
    val peerChoices = remember(activePeers, anyPeer) {
        listOf(anyPeer to null as String?) + activePeers.map { p ->
            "${p.hostname.ifEmpty { p.nodeId.take(8) }} · ${p.nodeId.take(4)}" to p.nodeId
        }
    }
    val peerLabel = peerChoices.firstOrNull { it.second == peerId }?.first ?: peerId ?: anyPeer
    val showPort = proto != "icmp" && proto != "any"

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Rf.Sheet,
        title = {
            Text(
                stringResource(R.string.allow_inbound),
                fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    PresetChip(stringResource(R.string.fw_preset_web)) {
                        action = "allow"; proto = "tcp"; port = "80,443"
                    }
                    PresetChip(stringResource(R.string.fw_preset_ssh)) {
                        direction = "in"; action = "allow"; proto = "tcp"; port = "22"
                    }
                    PresetChip(stringResource(R.string.fw_preset_all_tcp)) {
                        action = "allow"; proto = "tcp"; port = ""
                    }
                    PresetChip(stringResource(R.string.fw_preset_block_peer)) {
                        action = "deny"; proto = "any"; port = ""
                    }
                }
                if (lockedNetwork == null && networks.isNotEmpty()) {
                    RayfishDropdown(
                        value = scopeLabel,
                        options = scopeChoices.map { it.first },
                        onValueChange = { label ->
                            networkScope = scopeChoices.firstOrNull { it.first == label }?.second ?: ""
                        },
                        label = stringResource(R.string.fw_scope),
                    )
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishDropdown(
                        value = direction,
                        options = listOf("in", "out"),
                        onValueChange = { direction = it },
                        label = stringResource(R.string.fw_direction),
                        modifier = Modifier.weight(1f),
                    )
                    RayfishDropdown(
                        value = action,
                        options = listOf("allow", "deny"),
                        onValueChange = { action = it },
                        label = stringResource(R.string.fw_action),
                        modifier = Modifier.weight(1f),
                    )
                }
                RayfishDropdown(
                    value = peerLabel,
                    options = peerChoices.map { it.first },
                    onValueChange = { label ->
                        peerId = peerChoices.firstOrNull { it.first == label }?.second
                    },
                    label = stringResource(R.string.fw_peer),
                )
                RayfishDropdown(
                    value = proto,
                    options = listOf("tcp", "udp", "icmp", "any"),
                    onValueChange = { proto = it },
                    label = stringResource(R.string.fw_protocol),
                )
                if (showPort) {
                    RayfishTextField(port, { port = it.trim() }, stringResource(R.string.hint_port))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val peer = peerId
                val netArg = (lockedNetwork ?: networkScope).ifBlank { null }
                val portArg = if (showPort) port.ifBlank { null } else null
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            NodeHolder.get(context).firewallAdd(
                                direction, action, proto, portArg, peer, netArg,
                            )
                        }
                        onToast(context.getString(R.string.toast_rule_added))
                        onAdded()
                    } catch (t: Throwable) {
                        onToast(context.getString(R.string.error_add_failed, t.userMessage))
                    }
                }
            }) {
                Text(
                    stringResource(R.string.action_add_rule),
                    color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra)
            }
        },
    )
}

@Composable
private fun PresetChip(label: String, onClick: () -> Unit) {
    Surface(
        modifier = Modifier.clip(RoundedCornerShape(999.dp)).clickable(onClick = onClick),
        color = Rf.Card,
        shape = RoundedCornerShape(999.dp),
        border = BorderStroke(1.dp, Rf.CardBorder),
    ) {
        Text(
            label,
            fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Body,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
        )
    }
}
