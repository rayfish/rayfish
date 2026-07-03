package xyz.rayfish.android.ui.qr

import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.graphics.set
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/** Renders [content] as a QR code. White modules on transparent so it reads on the dark sheet. */
@Composable
fun QrImage(content: String, size: Dp = 180.dp, modifier: Modifier = Modifier) {
    val bitmap = remember(content) {
        val px = 512
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, px, px)
        Bitmap.createBitmap(px, px, Bitmap.Config.ARGB_8888).apply {
            for (x in 0 until px) for (y in 0 until px) {
                this[x, y] = if (matrix[x, y]) Color.WHITE else Color.TRANSPARENT
            }
        }
    }
    Image(bitmap = bitmap.asImageBitmap(), contentDescription = "QR code", modifier = modifier)
}

/** Camera QR scanner. Returns a lambda to launch it; [onResult] gets the decoded text or null. */
@Composable
fun rememberQrScanner(onResult: (String?) -> Unit): () -> Unit {
    val launcher = rememberLauncherForActivityResult(ScanContract()) { result ->
        onResult(result.contents)
    }
    return {
        launcher.launch(
            ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setBeepEnabled(false)
                .setPrompt("Scan a Rayfish code")
                .setOrientationLocked(false)
        )
    }
}
