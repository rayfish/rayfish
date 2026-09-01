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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
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
                onToast(context.messageForLinkAction(action))
                onChanged()
            } catch (t: Throwable) { onToast(context.getString(R.string.error_failed, t.message.orEmpty())) }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BrandHeader(title = stringResource(R.string.tab_you))
        SectionCard {
            SectionLabel(stringResource(R.string.label_this_device))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.device_name), fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                TextButton(onClick = { hostnameInput = deviceName; editing = true }) {
                    val hostnameShown = deviceName.ifEmpty { stringResource(R.string.action_set) }
                    Text(stringResource(R.string.hostname_edit, hostnameShown), fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Rose400)
                }
            }
            val nodeId = status?.nodeId?.takeIf { it.isNotEmpty() }
            val ip6 = status?.ipv6?.takeIf { it.isNotEmpty() }
            KeyValueRow(stringResource(R.string.label_node_id), nodeId?.let { if (it.length > 12) "${it.take(6)}…${it.takeLast(4)}" else it } ?: stringResource(R.string.dash),
                onClick = nodeId?.let { v -> { copyToClipboard(context, context.getString(R.string.label_node_id), v); onToast(context.getString(R.string.toast_copied_node_id)) } })
            KeyValueRow(stringResource(R.string.label_ipv6), ip6 ?: stringResource(R.string.dash), onClick = ip6?.let { v -> { copyToClipboard(context, context.getString(R.string.label_ipv6), v); onToast(context.getString(R.string.toast_copied, v)) } })
        }
        SectionCard {
            SectionLabel(stringResource(R.string.label_pairing))
            val running = status?.running == true
            if (!running) {
                Text(stringResource(R.string.pairing_need_tunnel),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
            } else if (paired) {
                Text(stringResource(R.string.pairing_already),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
                Spacer(Modifier.height(10.dp))
                OutlinePillButton(stringResource(R.string.pairing_unpair), onClick = { confirmUnpair = true }, modifier = Modifier.fillMaxWidth())
            } else {
                Text(stringResource(R.string.pairing_intro),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PillButton(stringResource(R.string.pairing_show_code), onClick = {
                        scope.launch {
                            try { pairingTicket = withContext(Dispatchers.IO) { NodeHolder.get(context).startPairing() } }
                            catch (t: Throwable) { onToast(context.getString(R.string.error_pairing_failed, t.message.orEmpty())) }
                        }
                    }, modifier = Modifier.weight(1f))
                    OutlinePillButton(stringResource(R.string.pairing_scan_code), onClick = scan, modifier = Modifier.weight(1f))
                }
            }
        }
        IdentityBackupCard(status = status, onToast = onToast, onChanged = onChanged)
        // Default off: standby is the normal behavior now, so disabling Rayfish
        // keeps files working with the VPN off (that is what lets you run another
        // VPN, Tailscale say, at the same time). This toggle is the escape hatch
        // for a user who wants disabling Rayfish to take the device fully offline
        // instead.
        var goOfflineWhenDisabled by remember { mutableStateOf(NodeHolder.isGoOfflineWhenDisabled(context)) }
        ToggleCard(
            title = stringResource(R.string.pref_go_offline),
            subtitle = if (goOfflineWhenDisabled) {
                stringResource(R.string.pref_go_offline_on)
            } else {
                stringResource(R.string.pref_go_offline_off)
            },
            checked = goOfflineWhenDisabled,
            onCheckedChange = { on ->
                goOfflineWhenDisabled = on
                NodeHolder.setGoOfflineWhenDisabled(context, on)
                // status is a poll cache (RayfishApp refreshes it every 2s), and is
                // null right after an Activity recreation: it can read stale-false
                // while the VPN just came up in Home, or stale-true right after Home
                // just took it down. Deciding from it here can silently kill a live
                // VPN or silently no-op a real request. The service's tunnel field is
                // authoritative only once the service re-checks it on nodeExecutor
                // (the thread that writes it), so send unconditionally and let the
                // service decide there instead of guessing from this stale cache.
                if (on) {
                    // The user asked to go fully offline when disabled. Do not send
                    // bare ACTION_STOP: that unconditionally tears down whatever is
                    // running, which is correct for Home's VPN toggle but not here,
                    // since a live VPN must not be touched by this pref.
                    // ACTION_EXIT_STANDBY means "if there is no tunnel, take the node
                    // fully offline and stop the service; if there is a tunnel, leave
                    // it alone, since the pref only governs the next teardown."
                    context.startService(
                        Intent(context, RayfishVpnService::class.java).apply {
                            action = RayfishVpnService.ACTION_EXIT_STANDBY
                        },
                    )
                } else {
                    // Back to the default: bring the control plane up in standby if
                    // the VPN is currently off. Bring the control plane up only,
                    // never a tunnel: a plain intent would land in startTunnel() and
                    // try to grab the single VpnService slot (and pop the consent
                    // dialog), which is exactly what standby exists to avoid when
                    // another VPN (Tailscale) is meant to hold that slot.
                    // ACTION_STANDBY routes to enterStandbyBlocking() on nodeExecutor.
                    // If a tunnel is up, it re-posts the notification to correct text
                    // instead of entering standby.
                    ContextCompat.startForegroundService(
                        context,
                        Intent(context, RayfishVpnService::class.java).apply {
                            action = RayfishVpnService.ACTION_STANDBY
                        },
                    )
                }
            },
        )
        var autoAcceptOwn by remember { mutableStateOf(NodeHolder.isAutoAcceptOwnDevices(context)) }
        ToggleCard(
            title = stringResource(R.string.pref_auto_accept),
            subtitle = if (autoAcceptOwn) stringResource(R.string.pref_auto_accept_on) else stringResource(R.string.pref_auto_accept_off),
            checked = autoAcceptOwn,
            onCheckedChange = { on ->
                autoAcceptOwn = on
                NodeHolder.setAutoAcceptOwnDevices(context, on)
            },
        )
        var crashReporting by remember { mutableStateOf(NodeHolder.isCrashReportingEnabled(context)) }
        ToggleCard(
            title = stringResource(R.string.pref_crash_reporting),
            subtitle = if (crashReporting) stringResource(R.string.pref_crash_reporting_on) else stringResource(R.string.pref_crash_reporting_off),
            checked = crashReporting,
            onCheckedChange = { on ->
                crashReporting = on
                NodeHolder.setCrashReportingEnabled(context, on)
                if (on) Telemetry.enable(context) else Telemetry.disable()
            },
        )
        if (crashReporting) {
            PillButton(stringResource(R.string.action_send_diagnostics), onClick = {
                scope.launch {
                    val id = withContext(Dispatchers.IO) {
                        runCatching { Telemetry.sendDiagnostics(context) }.getOrNull()
                    }
                    onToast(context.getString(if (id != null) R.string.toast_diagnostics_sent else R.string.toast_diagnostics_unavailable))
                }
            }, modifier = Modifier.fillMaxWidth())
        }
        SectionCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.label_about), fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                Text(stringResource(R.string.about_version, version), fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Muted)
            }
        }
    }

    if (editing) {
        AlertDialog(
            onDismissRequest = { editing = false },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.device_name), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishTextField(hostnameInput, { hostnameInput = it }, stringResource(R.string.hint_hostname))
                    Text(stringResource(R.string.device_name_applies), fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint)
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
                            onToast(context.getString(R.string.toast_device_name_set)); onChanged(); editing = false
                        } catch (t: Throwable) { onToast(context.getString(R.string.error_invalid_name, t.message.orEmpty())) }
                    }
                }) { Text(stringResource(R.string.action_save), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { editing = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    if (confirmUnpair) {
        AlertDialog(
            onDismissRequest = { confirmUnpair = false },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.unpair_title), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Text(stringResource(R.string.unpair_body),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Body)
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmUnpair = false
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { NodeHolder.get(context).unpair() }
                            paired = false
                            onToast(context.getString(R.string.toast_unpaired)); onChanged()
                        } catch (t: Throwable) { onToast(context.getString(R.string.error_unpair_failed, t.message.orEmpty())) }
                    }
                }) { Text(stringResource(R.string.action_unpair), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { confirmUnpair = false }) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) } },
        )
    }
    pairingTicket?.let { t -> QrCodeSheet(stringResource(R.string.qr_pairing_title), t, context) { pairingTicket = null } }
}
