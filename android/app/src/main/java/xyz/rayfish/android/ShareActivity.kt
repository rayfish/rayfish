package xyz.rayfish.android

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.PeerConnState
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.Rf
import xyz.rayfish.android.ui.theme.Chakra
import xyz.rayfish.android.ui.theme.PlexMono
import xyz.rayfish.android.ui.theme.RayfishTheme

/** A recipient in the share picker: one peer from the roster, resolved for sending. */
private data class Target(
    val nodeId: String,
    val hostname: String,
    val network: String,
    val ipv6: String,
    val state: PeerConnState,
)

/**
 * Share-sheet target for "Share with Rayfish". Receives ACTION_SEND /
 * ACTION_SEND_MULTIPLE, shows a picker of peers, and hands the chosen peer +
 * the shared URIs to [SendService] for background delivery. The activity finishes
 * as soon as the user picks (or cancels) — the actual send happens in the service.
 *
 * The picker lists idle and offline peers, not just connected ones. Mobile runs
 * the core in on-demand mode, so every mesh link self-closes after the idle
 * timeout: filtering on a live connection hid peers that were sitting right
 * there, reachable, and left the user with "No peers online". The core has never
 * needed a live link to send (an offer resolves against the roster and queues in
 * the outbox), so the only thing the old filter bought was a false negative.
 * [SendService] wakes the picked peer before offering, which is where the "is it
 * really reachable" answer comes from.
 */
class ShareActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uris = extractUris(intent)
        if (uris.isEmpty()) {
            finish()
            return
        }

        setContent {
            RayfishTheme {
                SharePicker(
                    itemCount = uris.size,
                    onPick = { target ->
                        dispatchSend(uris, target)
                        finish()
                    },
                    onCancel = { finish() },
                )
            }
        }
    }

    /** Read the shared content URIs from the incoming intent (single or multiple). */
    private fun extractUris(intent: Intent?): List<Uri> {
        intent ?: return emptyList()
        return when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri: Uri? =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM)
                    }
                listOfNotNull(uri)
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val list: ArrayList<Uri>? =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION") intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                    }
                list ?: emptyList()
            }
            else -> emptyList()
        }
    }

    /** Start [SendService], passing the URIs as ClipData so the read grant travels
     * with the intent (FLAG_GRANT_READ_URI_PERMISSION) and the service can stage
     * them after we finish. */
    private fun dispatchSend(uris: List<Uri>, target: Target) {
        val svc = Intent(this, SendService::class.java).apply {
            putExtra(SendService.EXTRA_PEER_ID, target.nodeId)
            putExtra(SendService.EXTRA_PEER_NAME, target.hostname.ifBlank { target.ipv6 })
            putParcelableArrayListExtra(SendService.EXTRA_URIS, ArrayList(uris))
            // Grant the service read access to every shared URI via ClipData.
            clipData = ClipData.newUri(contentResolver, "shared", uris.first()).apply {
                for (i in 1 until uris.size) addItem(ClipData.Item(uris[i]))
            }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        ContextCompat.startForegroundService(this, svc)
    }

    @Composable
    private fun SharePicker(itemCount: Int, onPick: (Target) -> Unit, onCancel: () -> Unit) {
        var targets by remember { mutableStateOf<List<Target>>(emptyList()) }
        var loading by remember { mutableStateOf(true) }

        // Bring the control plane up (idempotent) and poll status for peers.
        // Sending needs only the node started, not the tunnel; a peer shows up as
        // soon as it is in a roster, connected or not.
        LaunchedEffect(Unit) {
            withContext(Dispatchers.IO) { runCatching { NodeHolder.ensureStarted(applicationContext) } }
            repeat(40) {
                val list = withContext(Dispatchers.IO) { shareTargets() }
                targets = list
                loading = false
                delay(1500)
            }
        }

        Surface(color = Rf.Bg, modifier = Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                BrandHeader(title = stringResource(R.string.label_share))
                val label = pluralStringResource(R.plurals.share_item_count, itemCount, itemCount)
                Text(stringResource(R.string.share_send_to_peer, label), fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted)

                SectionCard {
                    SectionLabel(stringResource(R.string.label_peers))
                    when {
                        targets.isNotEmpty() -> targets.forEach { t ->
                            val (dot, note) = when (t.state) {
                                PeerConnState.ACTIVE -> Rf.Emerald to stringResource(R.string.peer_connected)
                                PeerConnState.IDLE -> Rf.Amber to stringResource(R.string.peer_idle)
                                PeerConnState.OFFLINE -> Rf.Faint to stringResource(R.string.peer_offline_queue)
                            }
                            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                                .clickable { onPick(t) }.padding(vertical = 9.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(dot))
                                Spacer(Modifier.width(9.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(t.hostname.ifEmpty { "?" }, fontFamily = Chakra,
                                        fontWeight = FontWeight.SemiBold, fontSize = 14.sp,
                                        color = if (t.state == PeerConnState.OFFLINE) Rf.Muted else Rf.Heading)
                                    Text(stringResource(R.string.share_peer_subtitle, t.ipv6, t.network, note), fontFamily = PlexMono,
                                        fontSize = 10.sp, color = Rf.Faint)
                                }
                            }
                        }
                        loading -> Text(stringResource(R.string.share_connecting), fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint)
                        else -> Text(stringResource(R.string.share_no_peers),
                            fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint)
                    }
                }

                OutlinePillButton(stringResource(R.string.action_cancel), onClick = onCancel, modifier = Modifier.fillMaxWidth())
            }
        }
    }

    /** Flatten every network's peers into a deduped target list (a peer that shares
     * several networks appears once, keyed by node id). Connected peers first, then
     * idle, then offline; alphabetical within each group so the list stays stable
     * across the 1.5s status refresh. A peer seen in two networks keeps its liveliest
     * state, since that is the one the send will actually use. */
    private fun shareTargets(): List<Target> {
        val status = runCatching { NodeHolder.get(applicationContext).status() }.getOrNull()
            ?: return emptyList()
        val byId = LinkedHashMap<String, Target>()
        for (net in status.networks) {
            for (p in net.peers) {
                val existing = byId[p.nodeId]
                if (existing != null && rank(existing.state) <= rank(p.state)) continue
                byId[p.nodeId] = Target(
                    nodeId = p.nodeId, hostname = p.hostname, network = net.name,
                    ipv6 = p.ipv6, state = p.state,
                )
            }
        }
        return byId.values.sortedWith(
            compareBy({ rank(it.state) }, { it.hostname.ifEmpty { it.ipv6 } }),
        )
    }

    private fun rank(state: PeerConnState): Int = when (state) {
        PeerConnState.ACTIVE -> 0
        PeerConnState.IDLE -> 1
        PeerConnState.OFFLINE -> 2
    }
}
