package xyz.rayfish.android

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import io.sentry.android.core.SentryLogcatAdapter as Log

/**
 * What "turn Rayfish on" and "turn Rayfish off" mean, in one place.
 *
 * Three entry points drive the tunnel (the Home toggle, the quick settings tile,
 * and the tile's consent shim) and they must all record the same enable intent
 * and send the same intent to the service. A caller that starts the service
 * without persisting the intent gets a tunnel the next app launch silently tears
 * down again, since [NodeHolder.isEnabled] is the authority for whether the
 * device should be online.
 *
 * Neither call raises the VPN consent dialog: [start] assumes consent is already
 * held (`VpnService.prepare` returned null). The callers own that check, because
 * only they know how to ask for it.
 */
object TunnelControl {
    private const val TAG = "TunnelControl"

    /**
     * Bring the tunnel up. Returns false if the system refused to start the
     * service, in which case nothing is coming up and the caller should not
     * report success.
     */
    fun start(context: Context): Boolean {
        // Record the intent before starting, so an app relaunch restores online.
        NodeHolder.setEnabled(context, true)
        return try {
            ContextCompat.startForegroundService(
                context, Intent(context, RayfishVpnService::class.java),
            )
            true
        } catch (t: Throwable) {
            // Android 12+ can refuse a foreground-service start made from the
            // background. The quick settings tile is the caller that could meet
            // this: the documented exemption list does not name tiles, even
            // though a tap normally leaves the process foreground enough for the
            // start to go through. Roll the enable intent back rather than leave
            // the app believing in a tunnel the user never got, which the next
            // launch would then try to restore.
            Log.e(TAG, "starting the VPN service was refused", t)
            NodeHolder.setEnabled(context, false)
            false
        }
    }

    /**
     * Take the tunnel down. The service decides what that means (standby by
     * default, fully offline if the user asked for it): this only delivers the
     * request, exactly as the notification's "Disable" action does.
     */
    fun stop(context: Context): Boolean {
        // Record the disable intent so the launch-time restore and the status
        // poll both keep the device offline until the user re-enables.
        NodeHolder.setEnabled(context, false)
        return try {
            context.startService(
                Intent(context, RayfishVpnService::class.java).apply {
                    action = RayfishVpnService.ACTION_STOP
                },
            )
            true
        } catch (t: Throwable) {
            // A plain background service start is restricted too. This only ever
            // runs while the tunnel is up, i.e. while our own foreground service
            // is running and the process is not in the background at all, so a
            // refusal here means the state we decided from was stale and there is
            // nothing left to stop. The enable intent above is already cleared,
            // which is the part that matters.
            Log.w(TAG, "stop request refused; assuming there is nothing running to stop", t)
            false
        }
    }
}
