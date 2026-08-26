package xyz.rayfish.android.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.RayException
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*
import java.io.ByteArrayOutputStream
import java.io.InputStream

/**
 * Back up and restore this device's identity.
 *
 * The destination is whatever the system file picker offers: Drive, OneDrive,
 * Files, a password manager that registers as a document provider. Deliberately
 * not the Drive API, which would cost Play Services, an OAuth client and app
 * verification to save a tap, and would take the F-Droid build with it. The
 * blob is encrypted before it ever leaves the process, so the provider the user
 * picks is not trusted with anything.
 *
 * The same code restores on desktop with `ray pair restore <code>`.
 */
@Composable
fun IdentityBackupCard(status: Status?, onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var askBackupPassword by remember { mutableStateOf(false) }
    var backupPassword by remember { mutableStateOf("") }
    var backupConfirm by remember { mutableStateOf("") }

    // The encrypted code, held only between "encrypted it" and "the user chose
    // where it goes". Cleared on both the success and the cancel path: a backup
    // code sitting in composition after the flow ends is the identity sitting
    // there, and a cancelled save is cheap to redo.
    var pendingCode by remember { mutableStateOf<String?>(null) }

    var restoreCode by remember { mutableStateOf<String?>(null) }
    var restorePassword by remember { mutableStateOf("") }
    var askRestorePassword by remember { mutableStateOf(false) }
    // The identity already on this device, set when the core refuses to
    // overwrite it. Drives the confirm dialog; null means nothing to confirm.
    var identityToReplace by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    // The tunnel binds the endpoint to the current key, so the identity cannot
    // change under it. Restore is offered only with Rayfish off, which is also
    // the state a user restoring onto a fresh phone is already in.
    val running = status?.running == true

    val saveBackup = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri: Uri? ->
        val code = pendingCode
        pendingCode = null
        if (uri == null || code == null) return@rememberLauncherForActivityResult
        scope.launch {
            val wrote = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(code.toByteArray()) }
                        ?: error("no output stream")
                }.isSuccess
            }
            onToast(if (wrote) "Backup saved" else "Could not write the backup")
        }
    }

    val pickBackup = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { readBounded(it) }
                }.getOrNull()
            }
            if (text.isNullOrBlank()) {
                onToast("Could not read that file")
            } else {
                restoreCode = text.trim()
                restorePassword = ""
                askRestorePassword = true
            }
        }
    }

    SectionCard {
        SectionLabel("Identity backup")
        Text(
            "Your identity is this device's key. Lose it and your networks do not know you; " +
                "back it up encrypted with a password only you know.",
            fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PillButton(
                "Back up",
                enabled = !busy,
                onClick = {
                    backupPassword = ""
                    backupConfirm = ""
                    askBackupPassword = true
                },
                modifier = Modifier.weight(1f),
            )
            OutlinePillButton(
                "Restore",
                enabled = !busy && !running,
                onClick = { pickBackup.launch(arrayOf("*/*")) },
                modifier = Modifier.weight(1f),
            )
        }
        if (running) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Turn Rayfish off to restore an identity.",
                fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint,
            )
        }
    }

    if (askBackupPassword) {
        AlertDialog(
            onDismissRequest = { askBackupPassword = false },
            containerColor = Rf.Sheet,
            title = { Text("Back up identity", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishTextField(backupPassword, { backupPassword = it }, "password", password = true)
                    RayfishTextField(backupConfirm, { backupConfirm = it }, "confirm password", password = true)
                    Text(
                        "There is no way to recover this password. Without it the backup is just noise.",
                        fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = backupPassword.isNotEmpty() && backupPassword == backupConfirm,
                    onClick = {
                        val password = backupPassword
                        askBackupPassword = false
                        backupPassword = ""
                        backupConfirm = ""
                        scope.launch {
                            busy = true
                            try {
                                val backup = withContext(Dispatchers.IO) {
                                    NodeHolder.get(context).backupIdentity(password)
                                }
                                pendingCode = backup.code
                                saveBackup.launch(suggestedFileName(backup.publicKey))
                            } catch (t: Throwable) {
                                onToast("Backup failed: ${t.message}")
                            } finally {
                                busy = false
                            }
                        }
                    },
                ) { Text("Continue", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = {
                TextButton(onClick = { askBackupPassword = false }) {
                    Text("Cancel", color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }

    if (askRestorePassword) {
        AlertDialog(
            onDismissRequest = { askRestorePassword = false; restoreCode = null },
            containerColor = Rf.Sheet,
            title = { Text("Restore identity", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    RayfishTextField(restorePassword, { restorePassword = it }, "backup password", password = true)
                    Text(
                        "The password you chose when you made this backup.",
                        fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = restorePassword.isNotEmpty(),
                    onClick = {
                        askRestorePassword = false
                        val code = restoreCode ?: return@TextButton
                        restore(
                            scope, context, code, restorePassword, false,
                            onToast, onChanged,
                            onBusy = { busy = it },
                            onExists = { identityToReplace = it },
                            onSettled = { restoreCode = null; restorePassword = "" },
                        )
                    },
                ) { Text("Restore", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = {
                TextButton(onClick = { askRestorePassword = false; restoreCode = null }) {
                    Text("Cancel", color = Rf.Body, fontFamily = Chakra)
                }
            },
        )
    }

    identityToReplace?.let { existing ->
        AlertDialog(
            onDismissRequest = { identityToReplace = null; restoreCode = null; restartNode(scope, context, onChanged) },
            containerColor = Rf.Sheet,
            title = { Text("Replace this identity?", fontFamily = Chakra, fontWeight = FontWeight.Bold, color = Rf.Heading) },
            text = {
                Text(
                    "This device already has identity ${shortId(existing)}. Restoring replaces it: " +
                        "the old one is gone from this device, its pairing certificate is deleted, and peers " +
                        "will see this device at a new address.",
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Body,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    identityToReplace = null
                    val code = restoreCode ?: return@TextButton
                    restore(
                        scope, context, code, restorePassword, true,
                        onToast, onChanged,
                        onBusy = { busy = it },
                        onExists = { },
                        onSettled = { restoreCode = null; restorePassword = "" },
                    )
                }) { Text("Replace", color = Rf.Rose400, fontFamily = Chakra, fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = {
                TextButton(onClick = {
                    identityToReplace = null
                    restoreCode = null
                    restartNode(scope, context, onChanged)
                }) { Text("Cancel", color = Rf.Body, fontFamily = Chakra) }
            },
        )
    }
}

/**
 * Stop the node, swap the key, bring it back up. The stop is what makes the
 * swap legal (the core refuses while the endpoint is bound), so every exit from
 * here restarts, including the failures: leaving the device silently offline
 * because a password was mistyped would be the worse bug.
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
    onChanged: () -> Unit,
    onBusy: (Boolean) -> Unit,
    onExists: (String) -> Unit,
    onSettled: () -> Unit,
) {
    scope.launch {
        onBusy(true)
        var awaitingConfirmation = false
        try {
            val restored = withContext(Dispatchers.IO) {
                NodeHolder.stopNode(context)
                NodeHolder.get(context).restoreIdentity(code, password, replaceExisting)
            }
            onToast("Restored identity ${shortId(restored)}")
        } catch (e: RayException.IdentityExists) {
            awaitingConfirmation = true
            onExists(e.v1)
        } catch (e: RayException.BadBackup) {
            onToast("Wrong password, or that file is not a backup")
        } catch (e: RayException.NodeRunning) {
            onToast("Turn Rayfish off before restoring")
        } catch (t: Throwable) {
            onToast("Restore failed: ${t.message}")
        } finally {
            onBusy(false)
        }
        if (!awaitingConfirmation) {
            onSettled()
            runCatching { NodeHolder.ensureStarted(context) }
            onChanged()
        }
    }
}

private fun restartNode(scope: CoroutineScope, context: android.content.Context, onChanged: () -> Unit) {
    scope.launch {
        runCatching { NodeHolder.ensureStarted(context) }
        onChanged()
    }
}

/** First six of the public key, which is how the rest of the UI names one. */
private fun shortId(publicKey: String): String =
    if (publicKey.length > 6) publicKey.take(6) else publicKey

private fun suggestedFileName(publicKey: String): String = "rayfish-identity-${shortId(publicKey)}.txt"

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
