package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.InboundPolicy
import uniffi.ray_mobile.InboundSettings
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*
import xyz.rayfish.android.ui.userMessage

/** The identity peers connect to and invite, plus the way to ask a peer to connect. */
@Composable
fun IdentityCard(status: Status?, onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    var connecting by rememberSaveable { mutableStateOf(false) }
    val running = status?.running == true
    SectionCard {
        SectionLabel(stringResource(R.string.label_identity))
        val identity = status?.identity
        KeyValueRow(
            stringResource(R.string.label_identity),
            identity?.let { if (it.length > 12) "${it.take(6)}…${it.takeLast(4)}" else it } ?: stringResource(R.string.dash),
            onClick = identity?.let { v ->
                { if (copyToClipboard(context, context.getString(R.string.label_identity), v)) onToast(context.getString(R.string.toast_copied_identity)) }
            },
        )
        Spacer(Modifier.height(10.dp))
        OutlinePillButton(
            stringResource(R.string.connect_peer_action), onClick = { connecting = true },
            enabled = running, modifier = Modifier.fillMaxWidth(),
        )
    }
    if (connecting) {
        IdentityDialog(
            title = stringResource(R.string.connect_peer_action),
            body = stringResource(R.string.connect_peer_body),
            confirmLabel = stringResource(R.string.action_send_request),
            onDismiss = { connecting = false },
            onToast = onToast,
        ) { peer ->
            NodeHolder.get(context).connectPeer(peer, null).also { onChanged() }
        }
    }
}

/** Who may send connect requests and invitations, and the block list. */
@Composable
fun InboundCard(running: Boolean, onToast: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var settings by remember { mutableStateOf<InboundSettings?>(null) }
    var saving by remember { mutableStateOf(false) }
    var blockInput by rememberSaveable { mutableStateOf("") }
    suspend fun reload() {
        settings = try { withContext(Dispatchers.IO) { NodeHolder.get(context).inboundSettings() } }
        catch (t: CancellationException) { throw t }
        catch (t: Exception) { settings }
    }
    fun change(call: () -> Unit, after: () -> Unit = {}) {
        if (saving) return
        saving = true
        scope.launch {
            try { withContext(Dispatchers.IO) { call() }; reload(); after() }
            catch (t: CancellationException) { throw t }
            catch (t: Exception) { onToast(context.getString(R.string.error_failed, t.userMessage)) }
            finally { saving = false }
        }
    }
    LaunchedEffect(running) { reload() }
    val enabled = running && settings != null && !saving
    SectionCard {
        SectionLabel(stringResource(R.string.inbound_title))
        Text(stringResource(R.string.inbound_description), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
        if (!running) {
            Text(stringResource(R.string.need_running), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Faint, modifier = Modifier.padding(top = 6.dp))
        }
        for (choice in InboundPolicy.entries) {
            val selected = settings?.policy == choice
            Row(
                Modifier.fillMaxWidth().selectable(
                    selected = selected, enabled = enabled, role = Role.RadioButton,
                    onClick = { if (!selected) change({ NodeHolder.get(context).setInboundPolicy(choice) }) },
                ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected, onClick = null, enabled = enabled)
                Text(
                    stringResource(when (choice) {
                        InboundPolicy.ANYONE -> R.string.inbound_anyone
                        InboundPolicy.KNOWN -> R.string.inbound_known
                        InboundPolicy.NOBODY -> R.string.inbound_nobody
                    }),
                    fontFamily = Chakra, fontSize = 14.sp, color = Rf.Heading,
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        SectionLabel(stringResource(R.string.label_blocked))
        val blocked = settings?.blocked.orEmpty()
        if (blocked.isEmpty()) {
            Text(stringResource(R.string.blocked_none), fontFamily = PlexMono, fontSize = 14.sp, color = Rf.Faint)
        }
        blocked.forEach { identity ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(identity, fontFamily = PlexMono, fontSize = 13.sp, color = Rf.Body, maxLines = 1,
                    overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                TextButton(enabled = enabled, onClick = { change({ NodeHolder.get(context).unblockPeer(identity) }) }) {
                    Text(stringResource(R.string.action_unblock), color = Rf.Rose400, fontFamily = Chakra, fontSize = 14.sp)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        RayfishTextField(blockInput, { blockInput = it }, stringResource(R.string.hint_block_identity))
        Spacer(Modifier.height(8.dp))
        OutlinePillButton(
            stringResource(R.string.action_block),
            onClick = { val peer = blockInput.trim(); change({ NodeHolder.get(context).blockPeer(peer) }) { blockInput = "" } },
            enabled = enabled && blockInput.isNotBlank(), modifier = Modifier.fillMaxWidth(),
        )
    }
}

/**
 * Ask for a peer identity and run [submit] with it off the main thread. Its
 * result is shown as a toast; a failure keeps the dialog open to fix the input.
 */
@Composable
fun IdentityDialog(
    title: String, body: String, confirmLabel: String,
    onDismiss: () -> Unit, onToast: (String) -> Unit, submit: (String) -> String,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        containerColor = Rf.Sheet,
        title = { Text(title, fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(body, fontFamily = Chakra, fontSize = 14.sp, color = Rf.Body)
                RayfishTextField(input, { input = it }, stringResource(R.string.hint_identity))
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && input.isNotBlank(), onClick = {
                busy = true
                val peer = input.trim()
                scope.launch {
                    try {
                        onToast(withContext(Dispatchers.IO) { submit(peer) })
                        onDismiss()
                    } catch (t: CancellationException) { throw t }
                    catch (t: Exception) { onToast(context.getString(R.string.error_failed, t.userMessage)) }
                    finally { busy = false }
                }
            }) { Text(confirmLabel, color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra) }
        },
    )
}
