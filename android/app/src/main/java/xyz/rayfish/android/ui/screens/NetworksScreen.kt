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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
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

    fun <T> run(block: suspend () -> T, ok: (T) -> Unit, errPrefix: String) {
        scope.launch {
            try { val r = withContext(Dispatchers.IO) { block() }; ok(r); onChanged() }
            catch (t: Throwable) { onToast("$errPrefix: ${t.message}") }
        }
    }

    val nets = status?.networks ?: emptyList()

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BrandHeader(title = "Networks") {
            PillButton("＋ Add", onClick = { showAdd = true })
        }
        if (nets.isEmpty()) {
            SectionCard { Text(if (starting) "Starting…" else "No networks yet. Add one to get started.",
                fontFamily = Chakra, fontSize = 13.sp, color = Rf.Muted) }
        }
        nets.forEach { net ->
            SectionCard {
                Row(Modifier.fillMaxWidth().clickable { onOpen(net) }, verticalAlignment = Alignment.CenterVertically) {
                    val anyOnline = net.peers.any { it.online }
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(if (anyOnline) Rf.Emerald else Rf.Faint))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(net.name, fontFamily = Chakra, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = Rf.Heading)
                        Text("${net.hostname.ifEmpty { net.ipv4 }} · ${net.peers.count { it.online }} online",
                            fontFamily = PlexMono, fontSize = 9.sp, color = Rf.Muted)
                    }
                    OverflowMenu(listOf(
                        MenuItem("Invite to share") {
                            run({ NodeHolder.get(context).invite(net.name) }, { inviteCode = it }, "Invite failed")
                        },
                        MenuItem("Copy address") {
                            copyToClipboard(context, "${net.hostname.ifEmpty { "address" }}", "${net.ipv4}")
                            onToast("Address copied")
                        },
                    ))
                }
            }
        }
    }

    if (showAdd) {
        AddNetworkSheet(
            onDismiss = { showAdd = false },
            onCreate = { name -> showAdd = false; run({ NodeHolder.get(context).create(name) }, { onToast("Created ${it.name}") }, "Create failed") },
            onSubmitCode = { code ->
                showAdd = false
                run({ NodeHolder.get(context).submitCode(code) }, { action ->
                    onToast(when (action) {
                        is uniffi.ray_mobile.LinkAction.Joined ->
                            if (action.v1.pending) "Join requested for ${action.v1.name} - waiting for approval"
                            else "Joined ${action.v1.name}"
                        is uniffi.ray_mobile.LinkAction.Paired -> "Device paired"
                    })
                }, "Failed")
            },
            onToast = onToast,
        )
    }
    inviteCode?.let { code ->
        QrCodeSheet(title = "Invite to share", code = code, context = context, onToast = onToast) { inviteCode = null }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddNetworkSheet(
    onDismiss: () -> Unit, onCreate: (String?) -> Unit, onSubmitCode: (String) -> Unit, onToast: (String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    val scan = rememberQrScanner { result -> if (result != null) onSubmitCode(result.trim()) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Rf.Sheet) {
        Column(Modifier.padding(20.dp).padding(bottom = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionLabel("Join or pair")
            RayfishTextField(code, { code = it }, "Invite or pairing code")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PillButton("Continue", onClick = { if (code.isNotBlank()) onSubmitCode(code.trim()) else onToast("Enter a code") }, modifier = Modifier.weight(1f))
                OutlinePillButton("Scan", onClick = scan, modifier = Modifier.weight(1f))
            }
            Spacer(Modifier.height(6.dp))
            SectionLabel("Create a network")
            RayfishTextField(name, { name = it }, "Name (optional)")
            PillButton("Create network", onClick = { onCreate(name.trim().ifEmpty { null }) }, modifier = Modifier.fillMaxWidth())
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrCodeSheet(title: String, code: String, context: android.content.Context, onToast: (String) -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = Rf.Sheet) {
        Column(Modifier.fillMaxWidth().padding(20.dp).padding(bottom = 24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
            SectionLabel(title)
            QrImage(code, size = 200.dp)
            Text(code, fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Muted, modifier = Modifier.fillMaxWidth())
            PillButton("Copy code", onClick = { copyToClipboard(context, "Rayfish code", code); onToast("Copied") }, modifier = Modifier.fillMaxWidth())
        }
    }
}

fun copyToClipboard(context: android.content.Context, label: String, text: String) {
    val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    cm.setPrimaryClip(android.content.ClipData.newPlainText(label, text))
}
