package xyz.rayfish.android

import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import io.sentry.android.core.SentryLogcatAdapter as Log

/**
 * Invisible shim that exists for one reason: [TunnelTileService] cannot show the
 * system VPN consent dialog, because only an Activity can. The tile launches this
 * when [VpnService.prepare] asks for consent (fresh install, or another VPN app
 * holds the single VpnService slot); it raises the dialog, starts the tunnel if
 * the user approves, and finishes. It has no UI of its own and never appears in
 * recents.
 *
 * Not reached in the common case: with consent already held the tile starts the
 * service directly and the shade stays where it is.
 */
class VpnConsentActivity : ComponentActivity() {

    // Registered as a field, before the activity is STARTED, as the API requires.
    private val consent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                Log.i(TAG, "VPN consent granted; starting the tunnel")
                TunnelControl.start(applicationContext)
            } else {
                Log.i(TAG, "VPN consent denied; leaving the tunnel off")
            }
            finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A recreation (rotation, say) redelivers onCreate while the dialog the
        // first instance launched is still up and its result still pending.
        // Launching a second one would stack two dialogs; leave this instance to
        // be finished by that pending result instead.
        if (savedInstanceState != null) return

        val prep = runCatching { VpnService.prepare(this) }.getOrElse { t ->
            Log.e(TAG, "VpnService.prepare threw; nothing to ask consent for", t)
            finish()
            return
        }
        if (prep == null) {
            // Consent landed between the tile's check and this launch (the user
            // approved us somewhere else, or the other VPN app released the slot).
            Log.i(TAG, "consent already held by the time the shim ran; starting the tunnel")
            TunnelControl.start(applicationContext)
            finish()
            return
        }
        try {
            consent.launch(prep)
        } catch (t: Throwable) {
            Log.e(TAG, "could not show the VPN consent dialog", t)
            finish()
        }
    }

    private companion object {
        const val TAG = "RayfishConsent"
    }
}
