package xyz.rayfish.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.RayException
import uniffi.ray_mobile.Status

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                RayfishScreen()
            }
        }
    }
}

@Composable
private fun RayfishScreen() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    var vpnOn by remember { mutableStateOf(false) }
    var invite by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<Status?>(null) }

    fun startService() {
        val intent = Intent(context, RayfishVpnService::class.java)
        ContextCompat.startForegroundService(context, intent)
        vpnOn = true
    }

    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startService()
        } else {
            scope.launch { snackbar.showSnackbar("VPN permission denied") }
        }
    }

    fun toggleVpn(on: Boolean) {
        if (on) {
            val prepare = VpnService.prepare(context)
            if (prepare != null) {
                consentLauncher.launch(prepare)
            } else {
                startService()
            }
        } else {
            val intent = Intent(context, RayfishVpnService::class.java).apply {
                action = RayfishVpnService.ACTION_STOP
            }
            context.startService(intent)
            vpnOn = false
        }
    }

    fun refreshStatus() {
        scope.launch {
            status = withContext(Dispatchers.IO) {
                NodeHolder.get(context).status()
            }
        }
    }

    fun join() {
        val code = invite.trim()
        if (code.isEmpty()) {
            scope.launch { snackbar.showSnackbar("Enter an invite code first") }
            return
        }
        scope.launch {
            val message = withContext(Dispatchers.IO) {
                try {
                    val info = NodeHolder.get(context).join(code)
                    "Joined ${info.name}"
                } catch (e: RayException) {
                    "Join failed: ${e.message}"
                } catch (t: Throwable) {
                    "Join failed: ${t.message}"
                }
            }
            snackbar.showSnackbar(message)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Text(
                text = "Rayfish",
                fontSize = 34.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = "Mesh node",
                fontSize = 15.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Card {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column {
                        Text("Tunnel", fontWeight = FontWeight.SemiBold)
                        Text(
                            if (vpnOn) "Running" else "Stopped",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = vpnOn, onCheckedChange = { toggleVpn(it) })
                }
            }

            Card {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Join a network", fontWeight = FontWeight.SemiBold)
                    OutlinedTextField(
                        value = invite,
                        onValueChange = { invite = it },
                        label = { Text("Invite code") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = { join() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Join")
                    }
                }
            }

            Card {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Status", fontWeight = FontWeight.SemiBold)
                        OutlinedButton(onClick = { refreshStatus() }) { Text("Refresh") }
                    }
                    val s = status
                    if (s == null) {
                        Text(
                            "No status yet",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        StatusRow("Running", s.running.toString())
                        StatusRow("Node ID", s.nodeId.ifEmpty { "-" })
                        StatusRow("IPv4", s.ipv4.ifEmpty { "-" })
                        StatusRow("IPv6", s.ipv6.ifEmpty { "-" })
                        StatusRow("Peers", s.peers.size.toString())
                        s.peers.forEach { p ->
                            Text(
                                "  ${p.ipv4}  ${p.nodeId}",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}
