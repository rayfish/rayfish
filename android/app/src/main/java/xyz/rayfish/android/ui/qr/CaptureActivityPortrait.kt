package xyz.rayfish.android.ui.qr

import com.journeyapps.barcodescanner.CaptureActivity

/**
 * Portrait-locked QR scanner activity.
 *
 * The library's default [CaptureActivity] follows the device sensor with no fixed
 * orientation, so on many phones the camera preview comes up rotated 90°
 * (sideways) during pairing. This app's UI is portrait-only, so we launch the
 * scanner through this subclass and pin it to portrait in the manifest. The scan
 * is started with `setOrientationLocked(false)` so the library keeps the manifest
 * orientation instead of re-locking to whatever it detects at launch.
 */
class CaptureActivityPortrait : CaptureActivity()
