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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*

/**
 * Back up and restore this device's identity, from the You tab.
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
    var busy by remember { mutableStateOf(false) }
    var restoring by remember { mutableStateOf(false) }

    // The encrypted code, held only between "encrypted it" and "the user chose
    // where it goes". Cleared on both the success and the cancel path: a backup
    // code sitting in composition after the flow ends is the identity sitting
    // there, and a cancelled save is cheap to redo.
    var pendingCode by remember { mutableStateOf<String?>(null) }

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
                enabled = !busy && !running && !restoring,
                onClick = { restoring = true },
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

    IdentityRestoreDialogs(
        active = restoring,
        onDone = { restoring = false },
        onToast = onToast,
        onRestored = onChanged,
    )

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
}

private fun suggestedFileName(publicKey: String): String = "rayfish-identity-${shortId(publicKey)}.txt"
