package xyz.rayfish.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import xyz.rayfish.android.ui.RayfishApp
import xyz.rayfish.android.ui.theme.RayfishTheme

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
            RayfishTheme {
                RayfishApp(
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
         * Bridges [onNewIntent] (no Compose context) to the running [RayfishApp]:
         * a fresh deep link while the activity is alive is dropped in here and the
         * Compose side observes it via [LaunchedEffect].
         */
        val pendingLinkUri = androidx.compose.runtime.mutableStateOf<String?>(null)
    }
}
