package xyz.rayfish.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import xyz.rayfish.android.ui.RayfishApp
import xyz.rayfish.android.ui.theme.RayfishTheme

class MainActivity : ComponentActivity() {

    /** Guards against handling the same launch intent twice (config change, recomposition). */
    private var handledIntentUri: String? = null

    // Registered here (before the activity is STARTED, as the API requires). The
    // result is ignored: if the user denies, the service still runs, only its
    // notification stays hidden, which is the pre-request behavior.
    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        maybeRequestNotificationPermission()
        // Only treat the launch intent's data as a NEW deep link on first creation.
        // On recreation (e.g. rotation) the same Intent is redelivered, but it was
        // already consumed by the first instance, so skip it here.
        val initialUri = if (savedInstanceState == null) intent?.data?.toString() else null
        if (initialUri != null) {
            intent?.data = null
        }
        setContent {
            RayfishTheme {
                RayfishApp(
                    initialLinkUri = initialUri,
                    alreadyHandled = { uri -> uri == handledIntentUri },
                    markHandled = { uri -> handledIntentUri = uri },
                )
            }
        }
    }

    /**
     * On Android 13+ POST_NOTIFICATIONS is a runtime permission that defaults to
     * denied, which silently suppresses even the foreground-service notification
     * (the VPN/standby status and the file-transfer progress). Ask for it on
     * launch if we don't already hold it. No-op below API 33, where the manifest
     * grant is enough.
     */
    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
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
         * Bridges [onNewIntent] (no Compose context) to the running [RayfishApp]:
         * a fresh deep link while the activity is alive is dropped in here and the
         * Compose side observes it via [LaunchedEffect].
         */
        val pendingLinkUri = androidx.compose.runtime.mutableStateOf<String?>(null)
    }
}
