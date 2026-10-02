package xyz.rayfish.android.ui.components

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import xyz.rayfish.android.R
import xyz.rayfish.android.ShareActivity

/** Keep every document's read grant alive through recipient selection and staging. */
internal fun sendFilesIntent(context: Context, uris: List<Uri>): Intent {
    require(uris.isNotEmpty())
    return Intent(context, ShareActivity::class.java).apply {
        action = Intent.ACTION_SEND_MULTIPLE
        type = "*/*"
        putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
        clipData = ClipData.newUri(context.contentResolver, "files", uris.first()).apply {
            uris.drop(1).forEach { addItem(ClipData.Item(it)) }
        }
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
}

@Composable
fun SendFilesButton(enabled: Boolean, onToast: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) {
            try { context.startActivity(sendFilesIntent(context, uris)) }
            catch (t: Exception) { onToast(context.getString(R.string.error_send_start)) }
        }
    }
    PillButton(
        stringResource(R.string.action_send_files),
        onClick = { picker.launch(arrayOf("*/*")) },
        enabled = enabled, modifier = modifier,
    )
}
