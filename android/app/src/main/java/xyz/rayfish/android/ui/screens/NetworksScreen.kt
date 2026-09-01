package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.isActive
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.qr.QrImage
import xyz.rayfish.android.ui.qr.rememberQrScanner
import xyz.rayfish.android.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworksScreen(
    status: Status?, starting: Boolean, onToast: (String) -> Unit,
    onChanged: () -> Unit, onOpen: (NetworkDetail) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var inviteCode by remember { mutableStateOf<String?>(null) }   // non-null -> show invite sheet

    fun <T> run(block: suspend () -> T, ok: (T) -> Unit, errRes: Int) {
        scope.launch {
            try { val r = withContext(Dispatchers.IO) { block() }; ok(r); onChanged() }
            catch (t: Throwable) { onToast(context.getString(errRes, t.message.orEmpty())) }
        }
    }

    val nets = status?.networks ?: emptyList()
    val running = status?.running == true

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BrandHeader(title = stringResource(R.string.tab_networks)) {
            PillButton(stringResource(R.string.action_add), onClick = { showAdd = true })
        }
        if (nets.isEmpty()) {
            SectionCard { Text(if (starting) stringResource(R.string.status_starting_ellipsis) else stringResource(R.string.networks_empty),
                fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted) }
        }
        nets.forEach { net ->
            SectionCard {
                Row(Modifier.fillMaxWidth().clickable { onOpen(net) }, verticalAlignment = Alignment.CenterVertically) {
                    // Amber while a saved network is still being restored, red
                    // when its restore failed or the tunnel is off, green once a
                    // peer is reachable, grey when up but nobody's connected.
                    val dot = when {
                        net.state == NetworkConnState.CONNECTING -> Rf.Amber
                        net.state == NetworkConnState.NOT_CONNECTED || !running -> Rf.Rose500
                        net.peers.any { it.isActive } -> Rf.Emerald
                        else -> Rf.Faint
                    }
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(dot))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(net.name, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                        // A network the daemon has not registered has no peer
                        // count worth printing. Say what it is doing instead, and
                        // why, when the daemon has recorded a reason.
                        val peersOnline = net.peers.count { it.isActive }
                        val line = when (net.state) {
                            NetworkConnState.CONNECTING -> stringResource(R.string.status_connecting_ellipsis)
                            NetworkConnState.NOT_CONNECTED ->
                                net.reason?.let { stringResource(R.string.status_not_connected_reason, it) }
                                    ?: stringResource(R.string.status_not_connected)
                            NetworkConnState.CONNECTED ->
                                if (running) pluralStringResource(R.plurals.network_peers_online, peersOnline, peersOnline)
                                else stringResource(R.string.status_offline)
                        }
                        Text(stringResource(R.string.network_row_subtitle, net.hostname.ifEmpty { net.ipv6 }, line),
                            fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Muted)
                    }
                    // The device's stable .ray DNS name in this network. Prefer
                    // it over the IP for "copy address": the hostname is what
                    // peers use and it does not change if the IP is reassigned.
                    val dns = net.hostname.takeIf { it.isNotEmpty() }?.let { "$it.${net.name}.ray" }
                    OverflowMenu(
                        header = dns,
                        items = listOf(
                            MenuItem(stringResource(R.string.menu_invite)) {
                                run({ NodeHolder.get(context).invite(net.name) }, { inviteCode = it }, R.string.error_invite_failed)
                            },
                            MenuItem(stringResource(R.string.menu_copy_address)) {
                                val address = dns ?: net.ipv6
                                copyToClipboard(context, context.getString(R.string.clipboard_address), address)
                                onToast(context.getString(R.string.toast_copied, address))
                            },
                        ),
                    )
                }
            }
        }
        val pending = status?.pendingNetworks ?: emptyList()
        pending.forEach { name ->
            SectionCard {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(Rf.Faint))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                        Text(stringResource(R.string.networks_waiting_approval), fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Muted)
                    }
                }
            }
        }
    }

    if (showAdd) {
        AddNetworkSheet(
            onDismiss = { showAdd = false },
            onCreate = { name -> showAdd = false; run({ NodeHolder.get(context).create(name) }, { onToast(context.getString(R.string.toast_created, it.name)) }, R.string.error_create_failed) },
            onSubmitCode = { code ->
                showAdd = false
                run({ NodeHolder.get(context).submitCode(code) }, { action ->
                    onToast(context.messageForLinkAction(action))
                }, R.string.error_failed)
            },
            onToast = onToast,
        )
    }
    inviteCode?.let { code ->
        QrCodeSheet(title = stringResource(R.string.invite_sheet_title), code = code, context = context) { inviteCode = null }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddNetworkSheet(
    onDismiss: () -> Unit, onCreate: (String?) -> Unit, onSubmitCode: (String) -> Unit, onToast: (String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    val context = LocalContext.current
    val scan = rememberQrScanner { result -> if (result != null) onSubmitCode(result.trim()) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Rf.Sheet) {
        Column(Modifier.padding(20.dp).padding(bottom = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionLabel(stringResource(R.string.label_join_or_pair))
            RayfishTextField(code, { code = it }, stringResource(R.string.hint_invite_or_pairing_code))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PillButton(stringResource(R.string.action_continue), onClick = { if (code.isNotBlank()) onSubmitCode(code.trim()) else onToast(context.getString(R.string.toast_enter_code)) }, modifier = Modifier.weight(1f))
                OutlinePillButton(stringResource(R.string.action_scan), onClick = scan, modifier = Modifier.weight(1f))
            }
            Spacer(Modifier.height(6.dp))
            SectionLabel(stringResource(R.string.label_create_a_network))
            RayfishTextField(name, { name = it }, stringResource(R.string.hint_network_name_optional))
            PillButton(stringResource(R.string.action_create_network), onClick = { onCreate(name.trim().ifEmpty { null }) }, modifier = Modifier.fillMaxWidth())
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrCodeSheet(title: String, code: String, context: android.content.Context, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Rf.Sheet) {
        // The sheet has its own window, drawn above the Scaffold that hosts the
        // snackbar, so a snackbar confirmation would be hidden behind it and the
        // copy would look like it did nothing. Confirm in the button instead.
        var taps by remember { mutableStateOf(0) }
        var copied by remember { mutableStateOf(false) }
        LaunchedEffect(taps) {
            if (taps > 0) {
                delay(2000)
                taps = 0
            }
        }
        Column(Modifier.fillMaxWidth().padding(20.dp).padding(bottom = 24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
            SectionLabel(title)
            QrImage(code, size = 200.dp)
            Text(code, fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Muted, modifier = Modifier.fillMaxWidth())
            PillButton(
                if (taps == 0) stringResource(R.string.action_copy_code) else if (copied) stringResource(R.string.action_copied) else stringResource(R.string.action_copy_failed),
                onClick = {
                    copied = copyToClipboard(context, context.getString(R.string.clipboard_code), code)
                    taps++
                },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** Returns false when the platform refused the write, so the caller can say so
 *  rather than claim a copy that never landed. */
fun copyToClipboard(context: android.content.Context, label: String, text: String): Boolean {
    val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
        ?: return false
    return try {
        cm.setPrimaryClip(android.content.ClipData.newPlainText(label, text))
        true
    } catch (t: Throwable) {
        android.util.Log.w("rayfish", "clipboard write failed", t)
        false
    }
}

fun android.content.Context.messageForLinkAction(
    action: uniffi.ray_mobile.LinkAction,
    pairedRes: Int = R.string.toast_device_paired,
): String = when (action) {
    is uniffi.ray_mobile.LinkAction.Joined ->
        if (action.v1.pending) getString(R.string.toast_join_requested, action.v1.name)
        else getString(R.string.toast_joined, action.v1.name)
    is uniffi.ray_mobile.LinkAction.Paired -> getString(pairedRes)
}
