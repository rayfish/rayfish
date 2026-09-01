package xyz.rayfish.android

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.sentry.android.core.SentryLogcatAdapter as Log

/**
 * Quick settings tile that toggles the mesh tunnel from the shade, without
 * opening the app.
 *
 * An entry point, not a second state machine: ON does what the Home toggle does,
 * OFF sends the same `ACTION_STOP` the notification's "Disable" action sends. So
 * the tile inherits the standby-versus-fully-offline behavior already decided in
 * [RayfishVpnService] instead of restating it.
 *
 * Deliberately NOT an active tile (no `META_DATA_ACTIVE_TILE` in the manifest).
 * A non-active tile is bound and gets [onStartListening] every time the panel
 * becomes visible, so what the user sees is read fresh from
 * [RayfishVpnService.tunnelUp] at that moment. An active tile skips that bind and
 * keeps showing whatever the app last pushed, which goes stale as soon as the
 * process is killed: the tunnel dies with it, the tile would still read "on", and
 * `requestListeningState` cannot correct it because nothing is alive to call it.
 * The cost of this choice is that a toggle made elsewhere while the shade is open
 * (the notification's Disable button, say) only reaches the tile when the panel is
 * next opened; `requestListeningState` does nothing for non-active tiles, so there
 * is no push path to use instead.
 */
class TunnelTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        render(RayfishVpnService.tunnelUp)
    }

    override fun onClick() {
        super.onClick()
        if (RayfishVpnService.tunnelUp) {
            Log.i(TAG, "tile tapped with the tunnel up; requesting stop")
            TunnelControl.stop(applicationContext)
            // Teardown runs on the service's own executor, so the tile leads the
            // real state here. If it somehow does not follow, the next time the
            // panel opens reads the truth.
            render(active = false)
            return
        }

        // prepare() == null means we already hold the VPN slot, which is the
        // common case: start straight from here and leave the shade alone. A
        // non-null intent means consent is missing (fresh install) or another VPN
        // app holds the single slot. Only an Activity can show that dialog.
        val needsConsent = runCatching { VpnService.prepare(this) != null }.getOrElse { t ->
            Log.w(TAG, "VpnService.prepare threw; assuming consent is needed", t)
            true
        }
        if (!needsConsent) {
            Log.i(TAG, "tile tapped; starting the tunnel")
            // Optimistic in the same way the Home toggle is: bring-up is
            // asynchronous, and a failure is corrected on the next panel open.
            // False means the system refused the start outright, so nothing is
            // coming up and the tile must not claim otherwise.
            render(active = TunnelControl.start(applicationContext))
            return
        }
        Log.i(TAG, "tile tapped without VPN consent; launching the consent shim")
        // Nothing can be shown over a locked screen, so ask for the unlock first
        // and launch from its callback.
        if (isLocked) unlockAndRun { launchConsent() } else launchConsent()
    }

    // Lint flags the deprecated Intent overload below without seeing the version
    // guard around it. It is deprecated from API 34, where the PendingIntent
    // branch takes over, and it is the only overload that exists at all before
    // that, so on minSdk 24 there is nothing else to call.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun launchConsent() {
        val intent = Intent(this, VpnConsentActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // The Intent overload throws UnsupportedOperationException from
                // API 34 on; the PendingIntent one replaces it.
                startActivityAndCollapse(
                    PendingIntent.getActivity(
                        this,
                        0,
                        intent,
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    ),
                )
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "could not launch the VPN consent shim from the tile", t)
        }
    }

    /**
     * Paint [active] onto the tile. The label is left to the manifest, where it
     * tracks the build type's app name; only the subtitle (API 29+) says what the
     * tile is currently doing. No-op before the system has handed us a tile.
     */
    private fun render(active: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (active) getString(R.string.tile_tunnel_on) else getString(R.string.tile_tunnel_off)
        }
        tile.updateTile()
    }

    private companion object {
        const val TAG = "RayfishTile"
    }
}
