package xyz.rayfish.android

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import uniffi.ray_mobile.FileOffer

@RunWith(RobolectricTestRunner::class)
@Config(application = android.app.Application::class)
class ReceiveServiceTest {
    @Test fun refusedServiceStartReleasesOfferForRetry() {
        var attempts = 0
        val context = object : ContextWrapper(RuntimeEnvironment.getApplication() as Context) {
            override fun startForegroundService(service: Intent): ComponentName? {
                attempts++
                throw IllegalStateException("service start refused")
            }
        }
        val offer = FileOffer(123uL, "peer", "example.txt", 12uL, "text/plain", false)
        repeat(2) {
            assertFalse(ReceiveService.startAccept(context, offer))
            assertFalse(ReceiveService.accepting.value.containsKey(offer.id))
        }
        assertEquals("a refused start must not suppress another attempt", 2, attempts)
    }
}
