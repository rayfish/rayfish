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
import androidx.compose.runtime.LaunchedEffect
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
import uniffi.ray_mobile.LinkAction
import uniffi.ray_mobile.NetworkInfo
import uniffi.ray_mobile.Status

class MainActivity : ComponentActivity() {

    /** Guards against handling the same launch intent twice (config change, recomposition). */
    private var handledIntentUri: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Only treat the launch intent's data as a NEW deep link on first creation.
        // On recreation (e.g. rotation) the same Intent is redelivered, but it was
        // already consumed by the first instance, so skip it here.
        val initialUri = if (savedInstanceState == null) intent?.data?.toString() else null
        if (initialUri != null) {
            intent?.data = null
        }
        setContent {
            MaterialTheme {
                RayfishScreen(
                    initialLinkUri = initialUri,
                    alreadyHandled = { uri -> uri == handledIntentUri },
                    markHandled = { uri -> handledIntentUri = uri },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val uri = intent.data?.toString()
        setIntent(intent.apply { data = null })
        if (uri != null && uri != handledIntentUri) {
            handledIntentUri = uri
            pendingLinkUri.value = uri
        }
    }

    companion object {
        /**
         * Bridges [onNewIntent] (no Compose context) to the running [RayfishScreen]:
         * a fresh deep link while the activity is alive is dropped in here and the
         * Compose side observes it via [LaunchedEffect].
         */
        val pendingLinkUri = androidx.compose.runtime.mutableStateOf<String?>(null)
    }
}

@Composable
private fun RayfishScreen(
    initialLinkUri: String?,
    alreadyHandled: (String) -> Boolean,
    markHandled: (String) -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    var vpnOn by remember { mutableStateOf(false) }
    var invite by remember { mutableStateOf("") }
    var networkName by remember { mutableStateOf("") }
    var ticket by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<Status?>(null) }
    var lastNetwork by remember { mutableStateOf<NetworkInfo?>(null) }
    var starting by remember { mutableStateOf(true) }

    // NodeHolder.ensureStarted() is itself concurrency-safe (a Mutex converges
    // concurrent callers onto a single Node.start()), so this just delegates and
    // survives Activity recreation since NodeHolder is a process-wide singleton.
    suspend fun ensureStarted() {
        NodeHolder.ensureStarted(context)
    }

    LaunchedEffect(Unit) {
        try {
            ensureStarted()
        } catch (t: Throwable) {
            snackbar.showSnackbar("Failed to start: ${t.message}")
        } finally {
            starting = false
        }
    }

    fun rayExceptionMessage(prefix: String, t: Throwable): String = "$prefix: ${t.message}"

    fun handleLinkAction(action: LinkAction) {
        when (action) {
            is LinkAction.Joined -> {
                lastNetwork = action.v1
                scope.launch { snackbar.showSnackbar("Joined ${action.v1.name}") }
            }
            is LinkAction.Paired -> {
                scope.launch { snackbar.showSnackbar("Paired") }
            }
        }
    }

    fun followLink(uri: String) {
        scope.launch {
            try {
                ensureStarted()
                val action = withContext(Dispatchers.IO) {
                    NodeHolder.get(context).handleLink(uri)
                }
                handleLinkAction(action)
            } catch (t: Throwable) {
                snackbar.showSnackbar(rayExceptionMessage("Link failed", t))
            }
        }
    }

    // Handle the intent the activity was created with, once.
    LaunchedEffect(initialLinkUri) {
        val uri = initialLinkUri
        if (uri != null && !alreadyHandled(uri)) {
            markHandled(uri)
            followLink(uri)
        }
    }

    // Handle deep links delivered to an already-running activity via onNewIntent.
    val pendingLinkUri = MainActivity.pendingLinkUri.value
    LaunchedEffect(pendingLinkUri) {
        val uri = pendingLinkUri
        if (uri != null) {
            followLink(uri)
            MainActivity.pendingLinkUri.value = null
        }
    }

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
            try {
                ensureStarted()
                status = withContext(Dispatchers.IO) {
                    NodeHolder.get(context).status()
                }
            } catch (t: Throwable) {
                snackbar.showSnackbar(rayExceptionMessage("Status failed", t))
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
            try {
                ensureStarted()
                val info = withContext(Dispatchers.IO) {
                    NodeHolder.get(context).join(code)
                }
                lastNetwork = info
                snackbar.showSnackbar("Joined ${info.name}")
            } catch (t: Throwable) {
                snackbar.showSnackbar(rayExceptionMessage("Join failed", t))
            }
        }
    }

    fun createNetwork() {
        val name = networkName.trim().ifEmpty { null }
        scope.launch {
            try {
                ensureStarted()
                val info = withContext(Dispatchers.IO) {
                    NodeHolder.get(context).create(name)
                }
                lastNetwork = info
                snackbar.showSnackbar("Created ${info.name}")
            } catch (t: Throwable) {
                snackbar.showSnackbar(rayExceptionMessage("Create failed", t))
            }
        }
    }

    fun pairDevice() {
        val code = ticket.trim()
        if (code.isEmpty()) {
            scope.launch { snackbar.showSnackbar("Enter a pairing ticket first") }
            return
        }
        scope.launch {
            try {
                ensureStarted()
                withContext(Dispatchers.IO) {
                    NodeHolder.get(context).pair(code)
                }
                snackbar.showSnackbar("Paired")
            } catch (t: Throwable) {
                snackbar.showSnackbar(rayExceptionMessage("Pair failed", t))
            }
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
                text = if (starting) "Starting…" else "Mesh node",
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
                    Text("Create a network", fontWeight = FontWeight.SemiBold)
                    OutlinedTextField(
                        value = networkName,
                        onValueChange = { networkName = it },
                        label = { Text("Name (optional)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = { createNetwork() },
                        enabled = !starting,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Create network")
                    }
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
                    Button(
                        onClick = { join() },
                        enabled = !starting,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Join")
                    }
                }
            }

            Card {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Pair a device", fontWeight = FontWeight.SemiBold)
                    OutlinedTextField(
                        value = ticket,
                        onValueChange = { ticket = it },
                        label = { Text("Pairing ticket") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = { pairDevice() },
                        enabled = !starting,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Pair device")
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
                        OutlinedButton(onClick = { refreshStatus() }, enabled = !starting) {
                            Text("Refresh")
                        }
                    }
                    val net = lastNetwork
                    if (net != null) {
                        StatusRow("Network", net.name)
                        StatusRow("Address", "${net.nodeId}.${net.name}.ray")
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
