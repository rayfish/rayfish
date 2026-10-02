package xyz.rayfish.android

import android.app.Application
import android.content.Intent
import android.net.Uri
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import xyz.rayfish.android.ui.components.sendFilesIntent

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class SendFilesIntentTest {
    @Test fun everySelectedDocumentTravelsWithAReadGrant() {
        val uris = listOf(Uri.parse("content://documents/first"), Uri.parse("content://documents/second"))
        val intent = sendFilesIntent(RuntimeEnvironment.getApplication(), uris)
        assertEquals(ShareActivity::class.java.name, intent.component?.className)
        assertEquals(Intent.ACTION_SEND_MULTIPLE, intent.action)
        assertNotEquals(0, intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION)
        // EXTRA_STREAM feeds the picker; ClipData carries permission to the next
        // activity even when the first selection activity is recreated or finishes.
        assertEquals(uris, intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java))
        assertEquals(uris, (0 until intent.clipData!!.itemCount).map { intent.clipData!!.getItemAt(it).uri })
    }
}
