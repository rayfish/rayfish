package xyz.rayfish.android.ui.qr

import com.journeyapps.barcodescanner.CaptureActivity

/**
 * A capture activity pinned to portrait.
 *
 * zxing's default [CaptureActivity] follows the rotation sensor, and
 * `ScanOptions.setOrientationLocked(true)` only locks to whatever the sensor
 * happens to read at launch. On foldables (Galaxy Z Fold) that reads landscape
 * and the preview comes up sideways. Forcing `screenOrientation="portrait"` on
 * the activity in the manifest is the reliable fix; this subclass exists only to
 * carry that manifest entry (see AndroidManifest.xml) and is wired in through
 * `ScanOptions.setCaptureActivity` in [rememberQrScanner].
 */
class PortraitCaptureActivity : CaptureActivity()
