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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.Rf
import xyz.rayfish.android.ui.theme.Chakra
import xyz.rayfish.android.ui.theme.PlexMono
import xyz.rayfish.android.ui.theme.RayfishTheme

/** A recipient in the share picker: a single online peer, resolved for sending. */
private data class Target(val nodeId: String, val hostname: String, val network: String, val ipv4: String)

/**
 * Share-sheet target for "Share with Rayfish". Receives ACTION_SEND /
 * ACTION_SEND_MULTIPLE, shows a picker of online peers, and hands the chosen peer +
 * the shared URIs to [SendService] for background delivery. The activity finishes
 * as soon as the user picks (or cancels) — the actual send happens in the service.
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
            putExtra(SendService.EXTRA_PEER_NAME, target.hostname.ifBlank { target.ipv4 })
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

        // Bring the control plane up (idempotent) and poll status for online peers.
        // Sending needs only the node started, not the tunnel; a peer shows up once
        // a live connection exists.
        LaunchedEffect(Unit) {
            withContext(Dispatchers.IO) { runCatching { NodeHolder.ensureStarted(applicationContext) } }
            repeat(40) {
                val list = withContext(Dispatchers.IO) { onlineTargets() }
                targets = list
                loading = false
                delay(1500)
            }
        }

        Surface(color = Rf.Bg, modifier = Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                BrandHeader(title = "Share")
                val label = if (itemCount == 1) "1 item" else "$itemCount items"
                Text("Send $label to a peer", fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted)

                SectionCard {
                    SectionLabel("Online peers")
                    when {
                        targets.isNotEmpty() -> targets.forEach { t ->
                            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                                .clickable { onPick(t) }.padding(vertical = 9.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(Rf.Emerald))
                                Spacer(Modifier.width(9.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(t.hostname.ifEmpty { "?" }, fontFamily = Chakra,
                                        fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Rf.Heading)
                                    Text("${t.ipv4} · ${t.network}.ray", fontFamily = PlexMono,
                                        fontSize = 10.sp, color = Rf.Faint)
                                }
                            }
                        }
                        loading -> Text("Connecting…", fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint)
                        else -> Text("No peers online. Open Rayfish and connect, then try again.",
                            fontFamily = PlexMono, fontSize = 11.sp, color = Rf.Faint)
                    }
                }

                OutlinePillButton("Cancel", onClick = onCancel, modifier = Modifier.fillMaxWidth())
            }
        }
    }

    /** Flatten every network's online peers into a deduped target list (a peer
     * that shares several networks appears once, keyed by node id). */
    private fun onlineTargets(): List<Target> {
        val status = runCatching { NodeHolder.get(applicationContext).status() }.getOrNull()
            ?: return emptyList()
        val seen = HashSet<String>()
        val out = ArrayList<Target>()
        for (net in status.networks) {
            for (p in net.peers) {
                if (!p.online) continue
                if (!seen.add(p.nodeId)) continue
                out.add(Target(nodeId = p.nodeId, hostname = p.hostname, network = net.name, ipv4 = p.ipv4))
            }
        }
        return out.sortedBy { it.hostname.ifEmpty { it.ipv4 } }
    }
}
