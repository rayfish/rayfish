package xyz.rayfish.android

import android.app.Application
import java.time.Duration
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = Application::class)
class DownloadsOutcomeTest {
    @Test fun saveCompletionRemovesItsDeadlineAndPreservesTheResult() {
        val key = TransferKey("test-peer", "completed-file", 1uL)
        try {
            DownloadsOutcome.markPending(key)
            assertEquals(45_001L, DownloadsOutcome.nextCheckDelayMs())
            ShadowSystemClock.advanceBy(Duration.ofSeconds(30))
            assertEquals(15_001L, DownloadsOutcome.nextCheckDelayMs())
            DownloadsOutcome.record(key, true)
            assertNull(DownloadsOutcome.nextCheckDelayMs())
            assertFalse(DownloadsOutcome.isPending(key))
            assertTrue(DownloadsOutcome.consume(key))
        } finally { DownloadsOutcome.clearPending(key) }
    }

    @Test fun stalledSaveExpiresWithoutLeavingAnIdleTimer() {
        val key = TransferKey("test-peer", "stalled-file", 1uL)
        try {
            DownloadsOutcome.markPending(key)
            ShadowSystemClock.advanceBy(Duration.ofMillis(45_001))
            assertFalse(DownloadsOutcome.isPending(key))
            assertNull(DownloadsOutcome.nextCheckDelayMs())
        } finally { DownloadsOutcome.clearPending(key) }
    }
}
