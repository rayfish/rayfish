package xyz.rayfish.android

import android.content.Context
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import uniffi.ray_mobile.FileChangeListener
import uniffi.ray_mobile.FileWatch

/** One queued reconciliation at most; a new event can advance a later deadline. */
internal class DemandTask(
    private val executor: ScheduledThreadPoolExecutor,
    private val action: () -> Long?,
) : AutoCloseable {
    private var closed = false
    private var pending: ScheduledFuture<*>? = null
    private var deadline = Long.MAX_VALUE
    private var generation = 0L

    init { executor.removeOnCancelPolicy = true }

    @Synchronized
    fun request(delayMs: Long = 0) {
        if (closed) return
        val at = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs)
        if (pending != null && deadline <= at) return
        pending?.cancel(false)
        deadline = at
        val ticket = ++generation
        pending = executor.schedule({
            synchronized(this) {
                if (closed || ticket != generation) return@schedule
                pending = null
                deadline = Long.MAX_VALUE
            }
            action()?.let { request(it) }
        }, delayMs, TimeUnit.MILLISECONDS)
    }

    @Synchronized
    override fun close() {
        closed = true
        pending?.cancel(false)
        pending = null
        executor.shutdownNow()
    }
}

/** Run every reconciliation even if another fails; only failures need a retry timer. */
internal fun reconcileFileStatus(
    accept: () -> Unit,
    transfers: () -> Unit,
    offers: () -> Unit,
): Long? {
    val accepted = runCatching(accept)
    val transferred = runCatching(transfers)
    val offered = runCatching(offers)
    return if (accepted.isSuccess && transferred.isSuccess && offered.isSuccess) {
        DownloadsOutcome.nextCheckDelayMs()
    } else 4_000L
}

/** Reconciles notifications on core changes, with no timer when files are idle. */
internal class FileStatusMonitor private constructor(private val context: Context) : AutoCloseable {
    private val reconciliation = Any()
    @Volatile var isClosed = false
        private set
    private var watch: FileWatch? = null
    private val work = DemandTask(ScheduledThreadPoolExecutor(1)) {
        synchronized(reconciliation) {
            if (isClosed) return@DemandTask null
            // A transient platform failure gets another chance without requiring
            // a new transfer event. Successful idle reconciliations arm no timer.
            reconcileFileStatus(
                accept = { FileAutoAccept.run(context) },
                transfers = { TransferNotifier.poll(context) },
                offers = { OfferNotifier.poll(context) },
            )
        }
    }

    private fun subscribe() {
        watch = NodeHolder.get(context).watchFiles(object : FileChangeListener {
            override fun onChange() { work.request() }
        })
    }

    override fun close() {
        // Wait out a current reconciliation before NodeHolder resets session ids.
        // Callback delivery only enqueues work and never takes this lock.
        synchronized(reconciliation) {
            if (isClosed) return
            isClosed = true
            watch?.cancel()
            watch?.close()
            watch = null
            work.close()
        }
        if (active === this) active = null
    }

    companion object {
        @Volatile private var active: FileStatusMonitor? = null

        fun start(context: Context): FileStatusMonitor {
            active?.close()
            return FileStatusMonitor(context.applicationContext).also {
                active = it
                try { it.subscribe() } catch (t: Throwable) { it.close(); throw t }
            }
        }

        /** Platform-only changes (Downloads completion, preferences, retries). */
        fun request(delayMs: Long = 0) { active?.work?.request(delayMs) }
        fun stop() { active?.close() }
    }
}
