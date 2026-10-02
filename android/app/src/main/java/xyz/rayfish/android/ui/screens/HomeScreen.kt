package xyz.rayfish.android.ui.screens

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.FileOffer
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.Status
import uniffi.ray_mobile.Transfer
import uniffi.ray_mobile.TransferState
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.OfferNotifier
import xyz.rayfish.android.R
import xyz.rayfish.android.ReceiveService
import xyz.rayfish.android.TunnelControl
import xyz.rayfish.android.formatSize
import xyz.rayfish.android.isActive
import xyz.rayfish.android.ui.AppSnapshot
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*

@Composable
fun HomeScreen(snapshot: AppSnapshot, starting: Boolean, onToast: (String) -> Unit, onOpenNetworks: () -> Unit = {}, onRefresh: () -> Unit = {}) {
    val status = snapshot.status
    val files = snapshot.files
    val connects = snapshot.connects
    val joins = snapshot.joins
    val queued = snapshot.queued
    val transfers = snapshot.transfers
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var vpnOn by rememberSaveable { mutableStateOf(NodeHolder.isEnabled(context)) }
    var pendingVpn by rememberSaveable { mutableStateOf<Boolean?>(null) }

    // Reflect the real data-plane state when status arrives, without stomping an in-flight toggle.
    LaunchedEffect(status) {
        val running = status?.running ?: return@LaunchedEffect
        val pending = pendingVpn
        when {
            pending == null -> vpnOn = running          // no user action in flight: follow the truth
            running == pending -> { vpnOn = running; pendingVpn = null }  // reached desired state: adopt and clear
            // else: still transitioning toward the user's choice - keep the optimistic vpnOn, do not stomp it
        }
    }

    fun startService() {
        // Shared with the quick settings tile, so both entry points record the
        // same enable intent and start the service the same way. A false return
        // means the system refused the service start outright, so there is no
        // bring-up to be optimistic about and the toggle must stay where it is.
        if (!TunnelControl.start(context)) {
            onToast(context.getString(R.string.error_vpn_start))
            return
        }
        vpnOn = true
        pendingVpn = true
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) startService() else onToast(context.getString(R.string.error_vpn_denied))
    }
    fun toggle(on: Boolean) {
        if (on) {
            val prep = VpnService.prepare(context)
            if (prep != null) consent.launch(prep) else startService()
        } else {
            // Records the disable intent so the launch-time restore and the
            // status poll both keep the device offline until the user re-enables.
            TunnelControl.stop(context)
            vpnOn = false
            pendingVpn = false
        }
    }

    // A failed service startup must not strand an optimistic switch forever.
    LaunchedEffect(pendingVpn) {
        if (pendingVpn != null) {
            kotlinx.coroutines.delay(30_000)
            vpnOn = withContext(Dispatchers.IO) { NodeHolder.get(context).status().running }
            pendingVpn = null
            onToast(context.getString(R.string.error_vpn_start))
        }
    }

    val nets = status?.networks ?: emptyList()
    val online = nets.sumOf { n -> n.peers.count { it.isActive } }
    // Count only what the daemon has registered: the list also carries saved
    // networks that are still connecting, and this banner claims a working link.
    val connected = nets.count { it.state == NetworkConnState.CONNECTED }
    val running = status?.running == true
    val transitioning = starting || pendingVpn != null ||
        (running && nets.any { it.state == NetworkConnState.CONNECTING })
    val banner = when {
        starting -> stringResource(R.string.status_starting)
        pendingVpn == false -> stringResource(R.string.home_stopping)
        pendingVpn == true -> stringResource(R.string.status_connecting_ellipsis)
        !running && snapshot.controlPlaneRunning -> stringResource(R.string.home_files_available)
        !running -> stringResource(R.string.status_offline)
        nets.any { it.state == NetworkConnState.CONNECTING } -> stringResource(R.string.status_connecting_ellipsis)
        connected > 0 -> pluralStringResource(R.plurals.status_connected_networks, connected, connected)
        nets.isEmpty() -> stringResource(R.string.home_no_networks)
        else -> stringResource(R.string.home_connection_failed)
    }

    // `onFailure` is how a caller undoes what it staged before the call. A reject
    // that throws leaves the offer still pending core-side, so the notification
    // suppression taken out ahead of it has to come back off or that offer is
    // never announced again.
    fun act(onFailure: () -> Unit = {}, block: suspend () -> Unit) {
        scope.launch {
            try { withContext(Dispatchers.IO) { block() }; onRefresh() }
            catch (t: Throwable) { onFailure(); if (t is CancellationException) throw t; onToast(context.getString(R.string.error_failed, t.message.orEmpty())) }
        }
    }
    // The foreground service owns downloads, including their move to Downloads.
    // Observing its state keeps Save disabled across tab changes and recreation.
    val accepting by ReceiveService.accepting.collectAsStateWithLifecycle()
    fun acceptFile(f: FileOffer) {
        if (!ReceiveService.startAccept(context, f)) {
            onToast(context.getString(R.string.error_receive_start))
        }
    }

    val hasRequests = connects.isNotEmpty() || joins.isNotEmpty()
    val hasFiles = files.isNotEmpty() || accepting.isNotEmpty() || queued.isNotEmpty() || transfers.isNotEmpty()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BrandHeader()
        StatusEyebrow(connected = running && connected > 0 && !transitioning, text = banner, transitioning = transitioning)
        ToggleCard(
            title = stringResource(R.string.label_tunnel),
            subtitle = banner,
            checked = vpnOn, onCheckedChange = { toggle(it) },
        )
        SectionCard {
            SectionLabel(stringResource(R.string.label_networks))
            KeyValueRow(stringResource(R.string.label_networks), pluralStringResource(R.plurals.home_networks_peers, online, nets.size, online))
        }
        if (nets.isEmpty()) {
            PillButton(stringResource(R.string.home_join_network), onClick = onOpenNetworks, modifier = Modifier.fillMaxWidth())
        } else {
            SendFilesButton(enabled = nets.any { it.peers.isNotEmpty() }, onToast = onToast, modifier = Modifier.fillMaxWidth())
        }
        if (hasFiles) {
            SectionCard {
                SectionLabel(stringResource(R.string.label_files))
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    files.forEach { f ->
                        if (f.id in accepting) return@forEach
                        NotifRow(
                            title = f.filename,
                            subtitle = stringResource(R.string.home_file_from, formatSize(f.size), f.from),
                            acceptLabel = stringResource(R.string.action_save), onAccept = { acceptFile(f) },
                            onReject = {
                                OfferNotifier.markActedOn(context, f.id)
                                act(onFailure = { OfferNotifier.clearActedOn(f.id) }) {
                                    NodeHolder.get(context).rejectFileOffer(f.id)
                                }
                            },
                        )
                    }
                    queued.forEach { q ->
                        QueuedSendRow(
                            title = q.filename,
                            subtitle = stringResource(R.string.home_waiting_for_peer, q.peer, formatSize(q.size)),
                            onCancel = { act { NodeHolder.get(context).cancelSend(q.id) } },
                        )
                    }
                    transfers.sortedBy { it.state == TransferState.DONE || it.state == TransferState.FAILED }.forEach { t ->
                        val saving = !t.outgoing && t.state == TransferState.DONE &&
                            (accepting.values.any { t.matches(it) } || t.id in snapshot.savingTransfers)
                        TransferRow(t, saving, onCancel = { act { NodeHolder.get(context).cancelTransfer(t.id) } })
                    }
                    accepting.values.filter { f ->
                        transfers.none { it.matches(f) }
                    }.forEach { f -> FileTransferRow(f.filename) }
                }
            }
        }
        if (hasRequests) {
            SectionCard {
                SectionLabel(stringResource(R.string.label_requests))
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    connects.forEach { c ->
                        NotifRow(
                            title = c.hostname ?: c.shortId,
                            subtitle = stringResource(R.string.home_connect_request, c.shortId, c.waitingSecs.toInt()),
                            acceptLabel = stringResource(R.string.action_accept), onAccept = { act { NodeHolder.get(context).approveConnectRequest(c.shortId) } },
                            onReject = { act { NodeHolder.get(context).rejectConnectRequest(c.shortId) } },
                        )
                    }
                    joins.forEach { (net, j) ->
                        NotifRow(
                            title = j.hostname ?: j.shortId,
                            subtitle = stringResource(R.string.home_join_request, net, j.shortId),
                            acceptLabel = stringResource(R.string.action_accept), onAccept = { act { NodeHolder.get(context).acceptJoinRequest(net, j.shortId) } },
                            onReject = { act { NodeHolder.get(context).denyJoinRequest(net, j.shortId) } },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NotifRow(title: String, subtitle: String, acceptLabel: String, onAccept: () -> Unit, onReject: () -> Unit) {
    Column {
        Text(title, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading, maxLines = 1)
        Text(subtitle, fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onAccept, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
                Text(acceptLabel, color = Rf.Emerald, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
            }
            TextButton(onClick = onReject, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
                Text(stringResource(R.string.action_decline), color = Rf.Rose400, fontFamily = Chakra, fontSize = 14.sp)
            }
        }
    }
}

/// A send still waiting on its peer. One action only: there is nothing to accept
/// on this side, and once the peer takes the offer the row is gone anyway.
@Composable
private fun QueuedSendRow(title: String, subtitle: String, onCancel: () -> Unit) {
    Column {
        Text(title, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading, maxLines = 1)
        Text(subtitle, fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted)
        TextButton(onClick = onCancel, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
            Text(stringResource(R.string.action_cancel), color = Rf.Rose400, fontFamily = Chakra, fontSize = 14.sp)
        }
    }
}

@Composable
private fun TransferRow(transfer: Transfer, saving: Boolean, onCancel: () -> Unit) {
    val active = transfer.state == TransferState.OFFERED || transfer.state == TransferState.TRANSFERRING
    val label = when {
        saving -> stringResource(R.string.file_saving)
        transfer.state == TransferState.FAILED -> stringResource(R.string.file_failed)
        transfer.state == TransferState.DONE -> stringResource(if (transfer.outgoing) R.string.file_sent else R.string.file_received)
        transfer.state == TransferState.OFFERED -> stringResource(R.string.file_waiting)
        else -> stringResource(if (transfer.outgoing) R.string.file_sending else R.string.file_receiving)
    }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(transfer.filename, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp,
            color = Rf.Heading, maxLines = 2)
        Text(stringResource(R.string.file_transfer_detail, label, transfer.peer, formatSize(transfer.size)),
            fontFamily = PlexMono, fontSize = 12.sp,
            color = if (transfer.state == TransferState.FAILED) Rf.Rose400 else Rf.Muted)
        if (active || saving) {
            if (saving || transfer.state == TransferState.OFFERED || transfer.size == 0uL) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Rf.Rose500, trackColor = Rf.CardBorder)
            } else {
                LinearProgressIndicator(
                    progress = { (transfer.transferred.toDouble() / transfer.size.toDouble()).toFloat().coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(), color = Rf.Rose500, trackColor = Rf.CardBorder,
                )
                Text(stringResource(R.string.file_transfer_bytes, formatSize(transfer.transferred), formatSize(transfer.size)),
                    fontFamily = PlexMono, fontSize = 12.sp, color = Rf.Muted)
            }
            if (active && transfer.outgoing) TextButton(onClick = onCancel) {
                Text(stringResource(R.string.action_cancel), color = Rf.Rose400)
            }
        }
    }
}

@Composable
private fun FileTransferRow(filename: String) {
    Column {
        Text(filename, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading, maxLines = 1)
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            modifier = Modifier.fillMaxWidth(),
            color = Rf.Rose500,
            trackColor = Rf.CardBorder,
        )
    }
}

private fun Transfer.matches(offer: FileOffer): Boolean =
    !outgoing && peer == offer.from && filename == offer.filename && size == offer.size

@androidx.compose.ui.tooling.preview.Preview(backgroundColor = 0xFF18181B, showBackground = true)
@Composable
private fun HomePreview() {
    xyz.rayfish.android.ui.theme.RayfishTheme {
        HomeScreen(
            snapshot = AppSnapshot(status = Status(
                true, "7f3ac2e1", "200::7f3a",
                peers = emptyList(), networks = emptyList(), pendingNetworks = emptyList(),
            )),
            starting = false, onToast = {},
        )
    }
}
