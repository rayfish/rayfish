package xyz.rayfish.android.ui.screens

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.FileOffer
import uniffi.ray_mobile.PendingRequest
import uniffi.ray_mobile.Status
import xyz.rayfish.android.DownloadsOutcome
import xyz.rayfish.android.FileAutoAccept
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.TransferKey
import xyz.rayfish.android.TransferNotifier
import xyz.rayfish.android.moveToDownloads
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*
import java.io.File

@Composable
fun HomeScreen(status: Status?, starting: Boolean, onToast: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var vpnOn by remember { mutableStateOf(false) }
    var pendingVpn by remember { mutableStateOf<Boolean?>(null) }

    // Notifications: pending file offers, connect requests, and (for networks we
    // coordinate) join requests. Refetched on every status poll; surfaced as a
    // dialog when something needs a decision.
    var files by remember { mutableStateOf<List<FileOffer>>(emptyList()) }
    var connects by remember { mutableStateOf<List<PendingRequest>>(emptyList()) }
    var joins by remember { mutableStateOf<List<Pair<String, PendingRequest>>>(emptyList()) }

    // Reflect the real data-plane state when status arrives, without stomping an in-flight toggle.
    LaunchedEffect(status?.running) {
        val running = status?.running ?: return@LaunchedEffect
        val pending = pendingVpn
        when {
            pending == null -> vpnOn = running          // no user action in flight: follow the truth
            running == pending -> { vpnOn = running; pendingVpn = null }  // reached desired state: adopt and clear
            // else: still transitioning toward the user's choice - keep the optimistic vpnOn, do not stomp it
        }
    }

    fun startService() {
        // Record the intent before starting so an app relaunch restores online.
        NodeHolder.setEnabled(context, true)
        ContextCompat.startForegroundService(context, Intent(context, RayfishVpnService::class.java))
        vpnOn = true
        pendingVpn = true
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) startService() else onToast("VPN permission denied")
    }
    fun toggle(on: Boolean) {
        if (on) {
            val prep = VpnService.prepare(context)
            if (prep != null) consent.launch(prep) else startService()
        } else {
            // Record disable intent so the launch-time restore and the status
            // poll both keep the device offline until the user re-enables.
            NodeHolder.setEnabled(context, false)
            context.startService(Intent(context, RayfishVpnService::class.java).apply { action = RayfishVpnService.ACTION_STOP })
            vpnOn = false
            pendingVpn = false
        }
    }

    val nets = status?.networks ?: emptyList()
    val online = nets.sumOf { n -> n.peers.count { it.online } }
    val banner = when {
        starting -> "Starting"
        vpnOn -> "Connected · ${nets.size} network${if (nets.size == 1) "" else "s"}"
        else -> "Disconnected"
    }

    // Pending file/connect offers don't change `status`, so poll on our own timer
    // rather than keying off status. rememberUpdatedState keeps the coordinator
    // network list fresh inside the long-lived loop.
    val currentNets by rememberUpdatedState(nets)
    suspend fun reloadNotifs() {
        withContext(Dispatchers.IO) {
            val node = NodeHolder.get(context)
            // FileAutoAccept.run only starts own-device downloads on its bounded
            // executor and returns immediately; it does not wait for them to finish.
            // So an own-device offer is still present in listFileOffers() for the
            // whole download, and must be filtered out below rather than assumed
            // gone, or the user sees a manual "Save" row for a file that is already
            // downloading and can fire a second, concurrent accept for the same id.
            runCatching { FileAutoAccept.run(context) }
            // With the VPN off and stay-online off, RayfishVpnService is not running,
            // so this 2s loop is the only poller while the app is open: without this,
            // an own-device auto-accept (and any other in-flight transfer) would show
            // no progress and no result notification at all.
            runCatching { TransferNotifier.poll(context) }
            val autoAccepting = NodeHolder.isAutoAcceptOwnDevices(context)
            files = runCatching { node.listFileOffers() }.getOrDefault(emptyList())
                // Hide own-device offers while auto-accept is downloading or still
                // retrying them, but not ones it has permanently given up on: those
                // would otherwise be invisible with no way to save them at all.
                .filter { !(autoAccepting && it.ownDevice) || FileAutoAccept.hasGivenUp(it.id) }
            connects = runCatching { node.listConnectRequests() }.getOrDefault(emptyList())
            joins = currentNets.filter { it.isCoordinator }.flatMap { n ->
                runCatching { node.listJoinRequests(n.name) }.getOrDefault(emptyList()).map { n.name to it }
            }
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            runCatching { reloadNotifs() }
            kotlinx.coroutines.delay(2000)
        }
    }

    fun act(block: suspend () -> Unit) {
        scope.launch {
            try { withContext(Dispatchers.IO) { block() }; reloadNotifs() }
            catch (t: Throwable) { onToast("Failed: ${t.message}") }
        }
    }
    // The core writes into this app-private staging dir; we then move the file to
    // the device's public Downloads via MediaStore so it survives uninstall and
    // shows up in the Files/Downloads app.
    val saveDir = remember { context.getExternalFilesDir(null)?.absolutePath ?: context.filesDir.absolutePath }

    // In-place accept state: once Save is tapped, the file's row turns into a
    // progress bar (indeterminate: the core's accept is a single blocking call
    // with no byte-level progress), then a brief "Done!", then the row is gone.
    val accepting = remember { mutableStateMapOf<ULong, FileOffer>() }
    val doneFiles = remember { mutableStateMapOf<ULong, FileOffer>() }
    fun acceptFile(f: FileOffer) {
        accepting[f.id] = f
        val key = TransferKey(f.from, f.filename, f.size)
        // Mark pending before the blocking accept starts: the core reports the
        // transfer DONE from inside acceptFileOffer, before moveToDownloads below
        // has copied anything, so TransferNotifier's poller must see "pending"
        // from the first moment DONE can appear.
        DownloadsOutcome.markPending(key)
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    NodeHolder.get(context).acceptFileOffer(f.id, saveDir)
                    // Re-stamp pending now that the download is done and the copy
                    // is about to start: the first markPending call above only
                    // needed to cover the wait for DONE to appear, and acceptFileOffer
                    // can block far longer than PENDING_TIMEOUT_MS on a large file,
                    // which would otherwise expire the entry before the copy even
                    // begins.
                    DownloadsOutcome.markPending(key)
                    val reached = moveToDownloads(context, File(saveDir, f.filename), f.filename, f.mimeType)
                    DownloadsOutcome.record(key, reached)
                }
                accepting.remove(f.id)
                doneFiles[f.id] = f
                reloadNotifs()
                kotlinx.coroutines.delay(2000)
                doneFiles.remove(f.id)
            } catch (t: Throwable) {
                // The accept itself failed: no Downloads outcome is ever coming for
                // this key, so stop treating it as pending rather than making the
                // result notification wait out the timeout for a failure that has
                // already happened.
                DownloadsOutcome.clearPending(key)
                accepting.remove(f.id)
                onToast("Failed: ${t.message}")
            }
        }
    }

    val hasNotifs = files.isNotEmpty() || connects.isNotEmpty() || joins.isNotEmpty() ||
        accepting.isNotEmpty() || doneFiles.isNotEmpty()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BrandHeader()
        StatusEyebrow(connected = vpnOn && !starting, text = banner)
        ToggleCard(
            title = "Tunnel",
            subtitle = if (vpnOn) "running · this device ${status?.ipv4.orEmpty()}" else "stopped",
            checked = vpnOn, onCheckedChange = { toggle(it) },
        )
        SectionCard {
            SectionLabel("This device")
            val ip4 = status?.ipv4?.takeIf { it.isNotEmpty() }
            val ip6 = status?.ipv6?.takeIf { it.isNotEmpty() }
            KeyValueRow("IPv4", ip4 ?: "-", onClick = ip4?.let { v -> { copyToClipboard(context, "IPv4", v); onToast("Copied $v") } })
            KeyValueRow("IPv6", ip6 ?: "-", onClick = ip6?.let { v -> { copyToClipboard(context, "IPv6", v); onToast("Copied $v") } })
            KeyValueRow("Networks", "${nets.size} · $online peers online")
        }
        if (hasNotifs) {
            SectionCard {
                SectionLabel("Notifications")
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    files.forEach { f ->
                        if (f.id in accepting || f.id in doneFiles) return@forEach
                        NotifRow(
                            title = f.filename,
                            subtitle = "file · ${formatSize(f.size)} · from ${f.from}",
                            acceptLabel = "Save", onAccept = { acceptFile(f) },
                            onReject = { act { NodeHolder.get(context).rejectFileOffer(f.id) } },
                        )
                    }
                    accepting.values.forEach { f -> FileTransferRow(f.filename, done = false) }
                    doneFiles.values.forEach { f -> FileTransferRow(f.filename, done = true) }
                    connects.forEach { c ->
                        NotifRow(
                            title = c.hostname ?: c.shortId,
                            subtitle = "connect request · ${c.shortId} · ${c.waitingSecs}s",
                            acceptLabel = "Accept", onAccept = { act { NodeHolder.get(context).approveConnectRequest(c.shortId) } },
                            onReject = { act { NodeHolder.get(context).rejectConnectRequest(c.shortId) } },
                        )
                    }
                    joins.forEach { (net, j) ->
                        NotifRow(
                            title = j.hostname ?: j.shortId,
                            subtitle = "wants to join $net · ${j.shortId}",
                            acceptLabel = "Accept", onAccept = { act { NodeHolder.get(context).acceptJoinRequest(net, j.shortId) } },
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
        Text(title, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading, maxLines = 1)
        Text(subtitle, fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Muted)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onAccept, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
                Text(acceptLabel, color = Rf.Emerald, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
            }
            TextButton(onClick = onReject, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) {
                Text("Decline", color = Rf.Rose400, fontFamily = Chakra, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun FileTransferRow(filename: String, done: Boolean) {
    Column {
        Text(filename, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading, maxLines = 1)
        Spacer(Modifier.height(6.dp))
        if (done) {
            Text("Done!", fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, color = Rf.Emerald)
        } else {
            LinearProgressIndicator(
                modifier = Modifier.fillMaxWidth(),
                color = Rf.Rose500,
                trackColor = Rf.CardBorder,
            )
        }
    }
}

private fun formatSize(bytes: ULong): String {
    val b = bytes.toDouble()
    return when {
        b >= 1_000_000_000 -> "%.1f GB".format(b / 1_000_000_000)
        b >= 1_000_000 -> "%.1f MB".format(b / 1_000_000)
        b >= 1_000 -> "%.1f KB".format(b / 1_000)
        else -> "$bytes B"
    }
}

@androidx.compose.ui.tooling.preview.Preview(backgroundColor = 0xFF18181B, showBackground = true)
@Composable
private fun HomePreview() {
    xyz.rayfish.android.ui.theme.RayfishTheme {
        HomeScreen(
            status = Status(true, "7f3ac2e1", "100.88.0.3", "fd00::7f3a", emptyList(), emptyList(), emptyList()),
            starting = false, onToast = {},
        )
    }
}
