package xyz.rayfish.android.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.RayException
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*
import java.io.ByteArrayOutputStream
import java.io.InputStream

/**
 * The pick a file, type the password, swap the key sequence, shared by the two
 * places that offer it: the first-run screen and the You tab.
 *
 * Emits nothing until `active` goes true, at which point the system file picker
 * opens. `onDone` fires once the flow ends however it ends (restored, cancelled,
 * wrong password), so the caller can put its trigger back.
 */
@Composable
fun IdentityRestoreDialogs(
    active: Boolean,
    onDone: () -> Unit,
    onToast: (String) -> Unit,
    onRestored: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var code by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }
    var askPassword by remember { mutableStateOf(false) }
    // The identity already on this device, set when the core refuses to
    // overwrite it. Drives the confirm dialog; null means nothing to confirm.
    var identityToReplace by remember { mutableStateOf<String?>(null) }

    fun finish() {
        code = null
        password = ""
        onDone()
    }

    val pick = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) {
            finish()
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { readBounded(it) }
                }.getOrNull()
            }
            if (text.isNullOrBlank()) {
                onToast(context.getString(R.string.toast_restore_read_failed))
                finish()
            } else {
                code = text.trim()
                password = ""
                askPassword = true
            }
        }
    }

    // Opening the picker is a side effect of the flag going true, not of the
    // caller's click handler, so a caller only has to own one boolean.
    LaunchedEffect(active) {
        if (active) pick.launch(arrayOf("*/*"))
    }

    if (askPassword) {
        AlertDialog(
            onDismissRequest = { askPassword = false; finish() },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.restore_title), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishTextField(password, { password = it }, stringResource(R.string.hint_backup_password), password = true)
                    Text(
                        stringResource(R.string.restore_password_hint),
                        fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = password.isNotEmpty(),
                    onClick = {
                        askPassword = false
                        val c = code ?: return@TextButton
                        restore(
                            scope, context, c, password, false, onToast,
                            onExists = { identityToReplace = it },
                            onRestored = onRestored,
                            onSettled = ::finish,
                        )
                    },
                ) { Text(stringResource(R.string.action_restore), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = {
                TextButton(onClick = { askPassword = false; finish() }) {
                    Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }

    identityToReplace?.let { existing ->
        AlertDialog(
            onDismissRequest = { identityToReplace = null; finish() },
            containerColor = Rf.Sheet,
            title = { Text(stringResource(R.string.replace_identity_title), fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Text(
                    stringResource(R.string.replace_identity_body, shortId(existing)),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Body,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    identityToReplace = null
                    val c = code ?: return@TextButton
                    restore(
                        scope, context, c, password, true, onToast,
                        onExists = { },
                        onRestored = onRestored,
                        onSettled = ::finish,
                    )
                }) { Text(stringResource(R.string.action_replace), color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = {
                TextButton(onClick = { identityToReplace = null; finish() }) {
                    Text(stringResource(R.string.action_cancel), color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }
}

/**
 * Stop the node, swap the key, put the node back the way it was found.
 *
 * The stop is what makes the swap legal: the core refuses while the endpoint is
 * bound to the old key. Restarting is conditional on having stopped something,
 * which is what keeps this usable before first run. There, nothing is running
 * and nothing has minted a key yet, and an unconditional restart would mint one
 * the moment a password was mistyped, quietly ending the only window in which a
 * restore needs no warning.
 *
 * `onExists` fires when the device already holds a different identity, which is
 * a question for the user rather than an error. The node stays stopped in that
 * one case, because the answer is another call to this function.
 */
private fun restore(
    scope: CoroutineScope,
    context: android.content.Context,
    code: String,
    password: String,
    replaceExisting: Boolean,
    onToast: (String) -> Unit,
    onExists: (String) -> Unit,
    onRestored: () -> Unit,
    onSettled: () -> Unit,
) {
    scope.launch {
        val wasStarted = NodeHolder.isStarted()
        var awaitingConfirmation = false
        var restored = false
        try {
            val id = withContext(Dispatchers.IO) {
                NodeHolder.stopNode(context)
                NodeHolder.get(context).restoreIdentity(code, password, replaceExisting)
            }
            restored = true
            onToast(context.getString(R.string.toast_restored_identity, shortId(id)))
        } catch (e: RayException.IdentityExists) {
            awaitingConfirmation = true
            onExists(e.v1)
        } catch (e: RayException.BadBackup) {
            onToast(context.getString(R.string.toast_bad_backup))
        } catch (e: RayException.NodeRunning) {
            onToast(context.getString(R.string.toast_restore_need_off))
        } catch (t: Throwable) {
            onToast(context.getString(R.string.error_restore_failed, t.message.orEmpty()))
        }
        if (awaitingConfirmation) return@launch
        onSettled()
        if (wasStarted) runCatching { NodeHolder.ensureStarted(context) }
        if (restored) onRestored()
    }
}

/** First six of the public key, which is how the rest of the UI names one. */
internal fun shortId(publicKey: String): String =
    if (publicKey.length > 6) publicKey.take(6) else publicKey

/**
 * A backup code is about 126 characters. Reading unbounded would let a
 * mis-tapped video in the picker pull hundreds of megabytes into memory, so
 * stop well past any real code and let the decode reject what comes back.
 */
private const val MAX_BACKUP_FILE_BYTES = 4096

private fun readBounded(stream: InputStream): String {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(1024)
    while (out.size() < MAX_BACKUP_FILE_BYTES) {
        val n = stream.read(buf)
        if (n <= 0) break
        out.write(buf, 0, n)
    }
    return String(out.toByteArray(), Charsets.UTF_8)
}
