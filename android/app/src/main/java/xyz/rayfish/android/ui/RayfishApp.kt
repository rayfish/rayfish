package xyz.rayfish.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import android.content.Intent
import android.net.VpnService
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.NetworkDetail
import uniffi.ray_mobile.Status
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.ui.screens.*
import xyz.rayfish.android.ui.theme.Rf

enum class Tab(val label: String, val icon: ImageVector) {
    NETWORKS("Networks", Icons.Filled.Hub),
    HOME("Home", Icons.Filled.Home),
    YOU("You", Icons.Filled.AccountCircle),
}

@Composable
fun RayfishApp(initialLinkUri: String?, alreadyHandled: (String) -> Boolean, markHandled: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val lifecycleOwner = LocalLifecycleOwner.current

    var tab by remember { mutableStateOf(Tab.HOME) }
    var detail by remember { mutableStateOf<NetworkDetail?>(null) }
    var status by remember { mutableStateOf<Status?>(null) }
    var starting by remember { mutableStateOf(true) }

    // Observe only: never start the node here. The 2s poll used to call
    // ensureStarted(), which resurrected the node moments after the user
    // disabled it (it showed back online on the coordinator). The toggle is the
    // sole authority for the node's lifecycle now.
    suspend fun readStatus() {
        status = withContext(Dispatchers.IO) { NodeHolder.get(context).status() }
    }

    // On launch restore the tunnel only if the user left it enabled; otherwise
    // stay offline. Then poll every 2s while foregrounded; suspend in background.
    LaunchedEffect(Unit) {
        try {
            if (NodeHolder.isEnabled(context) && VpnService.prepare(context) == null) {
                ContextCompat.startForegroundService(
                    context, Intent(context, RayfishVpnService::class.java),
                )
            }
            readStatus()
        } catch (t: Throwable) { snackbar.showSnackbar("Failed to start: ${t.message}") }
        finally { starting = false }
    }
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                try { readStatus() } catch (_: Throwable) {}
                delay(2000)
            }
        }
    }

    fun toast(msg: String) { scope.launch { snackbar.showSnackbar(msg) } }
    fun refreshNow() { scope.launch { try { readStatus() } catch (_: Throwable) {} } }

    // Deep links: unchanged behavior, route to the joined/paired result.
    fun followLink(uri: String) {
        scope.launch {
            try {
                NodeHolder.ensureStarted(context)
                val action = withContext(Dispatchers.IO) { NodeHolder.get(context).handleLink(uri) }
                refreshNow()
                toast(when (action) {
                    is uniffi.ray_mobile.LinkAction.Joined -> "Joined ${action.v1.name}"
                    is uniffi.ray_mobile.LinkAction.Paired -> "Paired"
                })
            } catch (t: Throwable) { toast("Link failed: ${t.message}") }
        }
    }
    LaunchedEffect(initialLinkUri) {
        val uri = initialLinkUri
        if (uri != null && !alreadyHandled(uri)) { markHandled(uri); followLink(uri) }
    }
    val pending = xyz.rayfish.android.MainActivity.pendingLinkUri.value
    LaunchedEffect(pending) {
        if (pending != null) { followLink(pending); xyz.rayfish.android.MainActivity.pendingLinkUri.value = null }
    }

    Scaffold(
        containerColor = Rf.Bg,
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (detail == null) {
                NavigationBar(containerColor = Rf.Bg) {
                    Tab.entries.forEach { t ->
                        NavigationBarItem(
                            selected = tab == t,
                            onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = t.label) },
                            label = { Text(t.label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Rf.Rose400, selectedTextColor = Rf.Rose400,
                                unselectedIconColor = Rf.Faint, unselectedTextColor = Rf.Faint,
                                indicatorColor = Rf.Card,
                            ),
                        )
                    }
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding)) {
            val d = detail
            when {
                d != null -> NetworkDetailScreen(
                    detail = status?.networks?.firstOrNull { it.name == d.name } ?: d,
                    onBack = { detail = null }, onToast = ::toast, onChanged = ::refreshNow,
                    onLeft = { detail = null; refreshNow() },
                )
                tab == Tab.HOME -> HomeScreen(status = status, starting = starting, onToast = ::toast)
                tab == Tab.NETWORKS -> NetworksScreen(
                    status = status, starting = starting, onToast = ::toast,
                    onChanged = ::refreshNow, onOpen = { detail = it },
                )
                tab == Tab.YOU -> YouScreen(status = status, onToast = ::toast, onChanged = ::refreshNow)
            }
        }
    }
}
