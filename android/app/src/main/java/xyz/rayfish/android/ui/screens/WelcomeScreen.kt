package xyz.rayfish.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import xyz.rayfish.android.ui.components.*
import xyz.rayfish.android.ui.theme.*

/**
 * Shown once, on a device with no identity yet.
 *
 * It exists for one reason: restoring a backup has to be offered before
 * anything mints a key, because minting one turns a clean restore into a
 * "replace the identity you already have?" warning about a key that is four
 * seconds old. Everything the app does starts the node, and starting the node
 * mints, so the only place this can go is in front of all of it.
 *
 * [onDone] hands control back to the normal startup path, which is what brings
 * the node up. Nothing here starts it, and taking a wrong turn (cancelled
 * picker, mistyped password) leaves the device exactly as it was, so this screen
 * comes back next launch rather than stranding someone past it.
 */
@Composable
fun WelcomeScreen(onDone: () -> Unit) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var restoring by remember { mutableStateOf(false) }

    fun toast(msg: String) { scope.launch { snackbar.showSnackbar(msg) } }

    Scaffold(
        containerColor = Rf.Bg,
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            BrandHeader(title = stringResource(xyz.rayfish.android.R.string.app_name))
            Spacer(Modifier.weight(1f))
            SectionCard {
                SectionLabel(stringResource(xyz.rayfish.android.R.string.label_this_device))
                Text(
                    stringResource(xyz.rayfish.android.R.string.welcome_body),
                    fontFamily = Chakra, fontSize = 12.sp, color = Rf.Muted,
                )
                Spacer(Modifier.height(14.dp))
                PillButton(
                    stringResource(xyz.rayfish.android.R.string.welcome_get_started),
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !restoring,
                )
                Spacer(Modifier.height(8.dp))
                OutlinePillButton(
                    stringResource(xyz.rayfish.android.R.string.welcome_restore),
                    onClick = { restoring = true },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !restoring,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(xyz.rayfish.android.R.string.welcome_restore_hint),
                    fontFamily = PlexMono, fontSize = 10.sp, color = Rf.Faint,
                )
            }
            Spacer(Modifier.weight(1f))
        }
    }

    IdentityRestoreDialogs(
        active = restoring,
        onDone = { restoring = false },
        onToast = ::toast,
        onRestored = onDone,
    )
}
