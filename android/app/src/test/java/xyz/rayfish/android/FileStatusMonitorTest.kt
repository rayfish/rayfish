package xyz.rayfish.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class FileStatusMonitorTest {
    @Test fun coalescesRequestsAndAdvancesSaveDeadlineForNewEvents() {
        val executor = ScheduledThreadPoolExecutor(1)
        val called = CountDownLatch(1)
        val task = DemandTask(executor) { called.countDown(); null }
        try {
            repeat(100) { task.request(60_000) }
            assertEquals(1, executor.queue.size)
            task.request()
            assertTrue(called.await(2, TimeUnit.SECONDS))
            executor.submit {}.get(2, TimeUnit.SECONDS)
            assertTrue("no idle timer after reconciliation", executor.queue.isEmpty())
        } finally { task.close() }
    }

    @Test fun eventDuringReconciliationIsNotLost() {
        val executor = ScheduledThreadPoolExecutor(1)
        val called = CountDownLatch(2)
        val count = AtomicInteger()
        lateinit var task: DemandTask
        task = DemandTask(executor) {
            if (count.incrementAndGet() == 1) task.request()
            called.countDown()
            null
        }
        try {
            task.request()
            assertTrue(called.await(2, TimeUnit.SECONDS))
            executor.submit {}.get(2, TimeUnit.SECONDS)
            assertEquals(2, count.get())
            assertTrue(executor.queue.isEmpty())
        } finally { task.close() }
    }

    @Test fun pendingWorkCanRequestOneFollowupWithoutStartingAnIdleLoop() {
        val executor = ScheduledThreadPoolExecutor(1)
        val called = CountDownLatch(2)
        val count = AtomicInteger()
        val task = DemandTask(executor) {
            called.countDown()
            if (count.incrementAndGet() == 1) 0L else null
        }
        try {
            task.request()
            assertTrue(called.await(2, TimeUnit.SECONDS))
            executor.submit {}.get(2, TimeUnit.SECONDS)
            assertEquals(2, count.get())
            assertTrue(executor.queue.isEmpty())
        } finally { task.close() }
    }

    @Test fun closingCancelsDeadlinesAndRejectsLateCallbacks() {
        val executor = ScheduledThreadPoolExecutor(1)
        val task = DemandTask(executor) { fail("closed observer ran"); null }
        task.request(60_000)
        task.close()
        task.request()
        task.close()
        assertTrue(executor.isShutdown)
        assertTrue(executor.queue.isEmpty())
    }
}
