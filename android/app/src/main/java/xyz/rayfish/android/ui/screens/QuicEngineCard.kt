package xyz.rayfish.android.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.QuicEngine
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.ui.components.SectionCard
import xyz.rayfish.android.ui.components.SectionLabel
import xyz.rayfish.android.ui.theme.Chakra
import xyz.rayfish.android.ui.theme.Rf

@Composable
fun QuicEngineCard(onToast: (String) -> Unit, onChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var engine by remember { mutableStateOf<QuicEngine?>(null) }
    var saving by remember { mutableStateOf(false) }
    var needsRestart by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        try {
            engine = withContext(Dispatchers.IO) { NodeHolder.get(context).quicEngine() }
        } catch (t: Throwable) {
            onToast(context.getString(R.string.error_failed, t.message.orEmpty()))
        }
    }
    SectionCard {
        SectionLabel(stringResource(R.string.quic_engine_title))
        Text(stringResource(R.string.quic_engine_description), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
        for (choice in QuicEngine.entries) {
            val select = {
                if (engine != choice && !saving) {
                    saving = true
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { NodeHolder.get(context).setQuicEngine(choice) }
                            engine = choice
                            needsRestart = true
                            onChanged()
                        } catch (t: Throwable) {
                            onToast(context.getString(R.string.error_failed, t.message.orEmpty()))
                        } finally {
                            saving = false
                        }
                    }
                }
            }
            Row(
                Modifier.fillMaxWidth().selectable(
                    selected = engine == choice,
                    enabled = engine != null && !saving,
                    role = Role.RadioButton,
                    onClick = select,
                ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = engine == choice, onClick = null, enabled = engine != null && !saving)
                Text(
                    stringResource(if (choice == QuicEngine.STANDALONE) R.string.quic_engine_standalone else R.string.quic_engine_fq_codel),
                    fontFamily = Chakra, fontSize = 14.sp, color = Rf.Heading,
                )
            }
        }
        if (needsRestart) {
            Column {
                Text(stringResource(R.string.quic_engine_restart_hint), fontFamily = Chakra, fontSize = 14.sp, color = Rf.Muted)
                TextButton(enabled = !saving, onClick = {
                    try {
                        ContextCompat.startForegroundService(context, Intent(context, RayfishVpnService::class.java).apply {
                            action = RayfishVpnService.ACTION_RESTART_NODE
                        })
                        needsRestart = false
                    } catch (t: Throwable) {
                        onToast(context.getString(R.string.error_failed, t.message.orEmpty()))
                    }
                }) {
                    Text(stringResource(R.string.quic_engine_restart), fontFamily = Chakra, color = Rf.Rose400)
                }
            }
        }
    }
}
