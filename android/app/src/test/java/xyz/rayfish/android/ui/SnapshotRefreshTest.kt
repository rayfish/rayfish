package xyz.rayfish.android.ui

import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.*
import org.junit.Test
import uniffi.ray_mobile.Status

class SnapshotRefreshTest {
    @Test fun failedReadPreservesKnownDataAndRetryClearsTheError() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val known = AppSnapshot(status = status("device"), loaded = true)
        val calls = AtomicInteger()
        val reader = SnapshotRefresh(scope) {
            if (calls.incrementAndGet() == 2) throw IOException("temporarily unavailable")
            known
        }
        try {
            reader.request()
            withTimeout(2_000) { reader.state.first { it.loaded } }
            reader.request()
            val failed = withTimeout(2_000) { reader.state.first { it.refreshFailed } }
            assertSame(known.status, failed.status)
            reader.request()
            val recovered = withTimeout(2_000) { reader.state.first { !it.refreshFailed } }
            assertSame(known.status, recovered.status)
            assertEquals(3, calls.get())
        } finally { scope.cancel() }
    }

    @Test fun requestsDuringASlowReadBecomeOneFollowup() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val starts = Channel<Int>(Channel.UNLIMITED)
        val finish = Channel<Unit>(Channel.UNLIMITED)
        val calls = AtomicInteger()
        val reader = SnapshotRefresh(scope) {
            val id = calls.incrementAndGet()
            starts.send(id)
            finish.receive()
            AppSnapshot(status = status("read-$id"), loaded = true)
        }
        try {
            reader.request()
            assertEquals(1, withTimeout(2_000) { starts.receive() })
            repeat(100) { reader.request() }
            finish.send(Unit)
            assertEquals(2, withTimeout(2_000) { starts.receive() })
            finish.send(Unit)
            withTimeout(2_000) { reader.state.first { it.status?.nodeId == "read-2" } }
            assertNull("no redundant native reads while idle", withTimeoutOrNull(100) { starts.receive() })
            reader.request()
            assertEquals(3, withTimeout(2_000) { starts.receive() })
        } finally { scope.cancel() }
    }

    private fun status(id: String) = Status(false, id, "", emptyList(), emptyList(), emptyList())
}
