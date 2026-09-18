package xyz.rayfish.android

import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.ContextWrapper
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import uniffi.ray_mobile.FileOffer
import uniffi.ray_mobile.Transfer
import uniffi.ray_mobile.TransferState

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = Application::class)
class FileNotificationRetryTest {
    private class FailingContext(base: Context) : ContextWrapper(base) {
        var failures = 0

        override fun getSystemService(name: String): Any? {
            if (name == Context.NOTIFICATION_SERVICE && failures > 0) {
                failures--
                error("transient notification service failure")
            }
            return super.getSystemService(name)
        }
    }

    private lateinit var context: FailingContext
    private lateinit var notifications: NotificationManager
    private val offer = FileOffer(1uL, "peer", "file.txt", 10uL, "text/plain", false)
    private val key = TransferKey("peer", "file.txt", 10uL)

    @Before fun setUp() {
        context = FailingContext(RuntimeEnvironment.getApplication())
        notifications = context.getSystemService(NotificationManager::class.java)
        OfferNotifier.reset(context)
        TransferNotifier.reset(context)
        // Finish the stale-notification sweep and channel setup so injected
        // failures below happen when posting the actual notification.
        OfferNotifier.poll(context) { emptyList() }
        TransferNotifier.poll(context) { emptyList() }
        OfferNotifier.ensureChannel(context)
        TransferNotifier.ensureChannel(context)
    }

    @After fun tearDown() {
        context.failures = 0
        OfferNotifier.reset(context)
        TransferNotifier.reset(context)
        DownloadsOutcome.consume(key)
        notifications.cancelAll()
    }

    @Test fun failedOfferPostRetriesWithoutAnotherEventThenReturnsToIdle() {
        val executor = ScheduledThreadPoolExecutor(1)
        val attempts = AtomicInteger()
        val recovered = CountDownLatch(1)
        context.failures = 1
        val task = DemandTask(executor) {
            attempts.incrementAndGet()
            reconcileFileStatus({}, {}, { OfferNotifier.poll(context) { listOf(offer) } })
                .also { if (it == null) recovered.countDown() }
        }
        try {
            task.request() // The only event: the retry must schedule itself.
            assertTrue(recovered.await(8, TimeUnit.SECONDS))
            executor.submit {}.get(2, TimeUnit.SECONDS)
            assertEquals(2, attempts.get())
            assertEquals(offer.filename, notifications.activeNotifications.single()
                .notification.extras.getString(Notification.EXTRA_TITLE))
            assertTrue("successful reconciliation must leave no idle timer", executor.queue.isEmpty())
            notifications.cancelAll()
            assertNull(reconcileFileStatus({}, {}, { OfferNotifier.poll(context) { listOf(offer) } }))
            assertTrue("dismissed offers stay dismissed", notifications.activeNotifications.isEmpty())
        } finally { task.close() }
    }

    @Test fun failedCoreReadsRequestRetryInsteadOfReportingIdle() {
        assertEquals(4_000L, reconcileFileStatus({}, {}, {
            OfferNotifier.poll(context) { error("list offers failed") }
        }))
        assertEquals(4_000L, reconcileFileStatus({}, {
            TransferNotifier.poll(context) { error("list transfers failed") }
        }, {}))
        assertNull(reconcileFileStatus({},
            { TransferNotifier.poll(context) { emptyList() } },
            { OfferNotifier.poll(context) { emptyList() } },
        ))
    }

    @Test fun failedAutoAcceptStillReconcilesBothNotificationTypes() {
        val calls = mutableListOf<String>()
        assertEquals(4_000L, reconcileFileStatus(
            { calls.add("accept"); error("accept failed") },
            { calls.add("transfers") },
            { calls.add("offers") },
        ))
        assertEquals(listOf("accept", "transfers", "offers"), calls)
        assertNull(reconcileFileStatus({}, {}, {}))
    }

    @Test fun failedResultPostPreservesDownloadsOutcomeUntilRetrySucceeds() {
        val transfer = Transfer(1uL, false, "peer", "file.txt", 10uL, 10uL, TransferState.DONE)
        DownloadsOutcome.record(key, true)
        context.failures = 1
        val reconcile = {
            reconcileFileStatus({}, { TransferNotifier.poll(context) { listOf(transfer) } }, {})
        }
        assertEquals(4_000L, reconcile())
        assertTrue(DownloadsOutcome.peek(key))
        assertTrue(notifications.activeNotifications.isEmpty())
        assertNull(reconcile())
        assertEquals(context.getString(R.string.notif_saved_to_downloads),
            notifications.activeNotifications.single().notification.extras.getString(Notification.EXTRA_TEXT))
        assertFalse(DownloadsOutcome.peek(key))
        notifications.cancelAll()
        assertNull(reconcile())
        assertTrue("completed results are posted only once", notifications.activeNotifications.isEmpty())
    }

    @Test fun failedOfferCancellationKeepsBookkeepingForRetry() {
        OfferNotifier.poll(context) { listOf(offer) }
        context.failures = 1
        val reconcile = { reconcileFileStatus({}, {}, { OfferNotifier.poll(context) { emptyList() } }) }
        assertEquals(4_000L, reconcile())
        assertEquals(1, notifications.activeNotifications.size)
        assertNull(reconcile())
        assertTrue(notifications.activeNotifications.isEmpty())
    }
}
