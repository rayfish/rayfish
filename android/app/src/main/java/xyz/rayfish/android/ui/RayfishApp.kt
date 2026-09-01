package xyz.rayfish.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
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
import xyz.rayfish.android.R
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.ui.screens.*
import xyz.rayfish.android.ui.theme.Rf

enum class Tab(val labelRes: Int, val icon: ImageVector) {
    NETWORKS(R.string.tab_networks, Icons.Filled.Hub),
    HOME(R.string.tab_home, Icons.Filled.Home),
    YOU(R.string.tab_you, Icons.Filled.AccountCircle),
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

    // Null until the check completes, and everything below is composed only once
    // it is true. That ordering is the whole point: every path out of this
    // function starts the node, and the first start mints an identity, so a
    // first-run restore has to be offered in front of all of it. Null rather
    // than a default of false so an existing install never flashes the welcome
    // screen while a file is stat'ed.
    var hasIdentity by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(Unit) {
        hasIdentity = withContext(Dispatchers.IO) {
            // Treating a failure as "has one" keeps a reader that cannot answer
            // from offering to overwrite a key that may well be there.
            runCatching { NodeHolder.get(context).hasIdentity() }.getOrDefault(true)
        }
    }
    if (hasIdentity != true) {
        if (hasIdentity == false) WelcomeScreen(onDone = { hasIdentity = true })
        return
    }

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
            if (NodeHolder.isEnabled(context)) {
                if (VpnService.prepare(context) == null) {
                    ContextCompat.startForegroundService(
                        context, Intent(context, RayfishVpnService::class.java),
                    )
                } else {
                    // Another app (Tailscale, say) holds the single VpnService slot, so
                    // our saved enable intent is stale: it was set true when we still
                    // had the tunnel, but we can no longer get it back. Clear it now,
                    // the same reasoning onRevoke already uses, so the toggle stops
                    // reading "on" for a tunnel that will never come up, and the You
                    // screen's go-fully-offline control sees the real state instead of
                    // this leftover intent.
                    NodeHolder.setEnabled(context, false)
                    if (!NodeHolder.isGoOfflineWhenDisabled(context)) {
                        ContextCompat.startForegroundService(
                            context,
                            Intent(context, RayfishVpnService::class.java).apply {
                                action = RayfishVpnService.ACTION_STANDBY
                            },
                        )
                    }
                }
            } else if (!NodeHolder.isGoOfflineWhenDisabled(context)) {
                // The VPN is not being restored, and the user has not asked to go
                // fully offline when disabled, so standby is the default: files
                // should keep working. Nothing else brings the control plane up
                // after a process death; bring it up now via standby.
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, RayfishVpnService::class.java).apply {
                        action = RayfishVpnService.ACTION_STANDBY
                    },
                )
            }
            readStatus()
        } catch (t: Throwable) { snackbar.showSnackbar(context.getString(R.string.error_failed_to_start, t.message.orEmpty())) }
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
                toast(context.messageForLinkAction(action, R.string.toast_paired))
            } catch (t: Throwable) { toast(context.getString(R.string.error_link_failed, t.message.orEmpty())) }
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
                        val label = stringResource(t.labelRes)
                        NavigationBarItem(
                            selected = tab == t,
                            onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = label) },
                            label = { Text(label) },
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
