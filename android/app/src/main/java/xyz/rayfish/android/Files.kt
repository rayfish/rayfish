package xyz.rayfish.android

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.provider.OpenableColumns
import io.sentry.android.core.SentryLogcatAdapter as Log
import java.io.File
import java.util.UUID

/**
 * File-transfer helpers shared by the receive UI (HomeScreen), the outgoing share
 * flow (SendService), and the own-device auto-accept path.
 */

/**
 * Identifies one accept call's worth of work for [DownloadsOutcome], on both sides
 * of the accept (FileAutoAccept / HomeScreen's Save) and the later TransferNotifier
 * poll that reports the terminal result. There is no id shared across the FFI
 * boundary here: the offer id (FileOffer.id) and the transfer id the core assigns
 * once accept_file starts (Transfer.id) are two independent counters, and
 * Node.acceptFileOffer returns nothing that would let Kotlin learn the resulting
 * transfer id. (peer, filename, size) is the closest thing to unique available on
 * both sides; it only collides if the same peer sends two files with the same name
 * and size at the same time, an accepted rough edge, not a correctness requirement
 * here.
 */
internal data class TransferKey(val peer: String, val filename: String, val size: ULong)

/**
 * Whether the most recent [moveToDownloads] call for a given transfer actually
 * landed the file in the public Downloads collection, so [TransferNotifier] can
 * report the truth instead of assuming Downloads whenever a receive completes.
 *
 * The core reports a receive as DONE inside the blocking acceptFileOffer call,
 * before moveToDownloads (the MediaStore byte copy) even starts, so a poller can
 * observe DONE while the copy is still running. [markPending] records that a save
 * is in flight for a key *before* acceptFileOffer is called; TransferNotifier
 * checks [isPending] and, while true, defers posting the result entirely (and
 * does not mark the transfer terminal) rather than posting a guess that can be
 * permanently wrong. [record] (success) and [clearPending] (the accept itself
 * failed, so no Downloads outcome will ever be recorded) both clear it.
 */
internal object DownloadsOutcome {
    private val outcomes = java.util.Collections.synchronizedMap(HashMap<TransferKey, Boolean>())
    private val pending = java.util.Collections.synchronizedMap(HashMap<TransferKey, Long>())

    // A save that never completes (process death mid-copy, a wedged MediaStore
    // call) must not mute the result notification forever: past this much time
    // since markPending, isPending gives up waiting and lets the poller post
    // whatever it can determine (no Downloads claim, since none was ever
    // recorded). Comfortably under the core's 60s terminal-listability window, so
    // a poll still has time left to observe and post the terminal state once this
    // expires instead of the entry aging out of the registry unreported.
    private const val PENDING_TIMEOUT_MS = 45_000L

    fun markPending(key: TransferKey) {
        pending[key] = android.os.SystemClock.elapsedRealtime()
    }

    /** The accept itself failed before a Downloads outcome could ever be recorded
     * for this key: stop treating it as pending so the failure result can post on
     * the very next poll instead of waiting out [PENDING_TIMEOUT_MS]. */
    fun clearPending(key: TransferKey) {
        pending.remove(key)
    }

    fun isPending(key: TransferKey): Boolean {
        val since = pending[key] ?: return false
        if (android.os.SystemClock.elapsedRealtime() - since > PENDING_TIMEOUT_MS) {
            pending.remove(key)
            return false
        }
        return true
    }

    fun record(key: TransferKey, reachedDownloads: Boolean) {
        pending.remove(key)
        outcomes[key] = reachedDownloads
    }

    /** Consumes (removes) the recorded outcome so a later receive reusing the same
     * key does not read a stale value. Defaults to false (the neutral "Saved"
     * copy, no Downloads tap target) when nothing was recorded. */
    fun consume(key: TransferKey): Boolean = outcomes.remove(key) ?: false
}

/**
 * Copy [src] into the device's public Downloads collection via MediaStore and
 * delete the app-private staging copy. Returns true on success. On API < 29
 * (no scoped MediaStore Downloads) it leaves the file in place and returns
 * false, so the caller can report the fallback location.
 */
internal fun moveToDownloads(context: Context, src: File, displayName: String, mime: String): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
    if (!src.exists()) return false
    val resolver = context.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.Downloads.DISPLAY_NAME, displayName)
        if (mime.isNotEmpty()) put(MediaStore.Downloads.MIME_TYPE, mime)
        put(MediaStore.Downloads.IS_PENDING, 1)
    }
    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return false
    return try {
        resolver.openOutputStream(uri)?.use { out -> src.inputStream().use { it.copyTo(out) } }
            ?: return false
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
        src.delete()
        true
    } catch (t: Throwable) {
        resolver.delete(uri, null, null)
        false
    }
}

/**
 * Resolve a content [uri]'s user-visible file name (OpenableColumns.DISPLAY_NAME),
 * falling back to the last path segment or a generated name. Sanitized to a plain
 * file name (no path separators) so it is safe to use as a leaf file name.
 */
internal fun queryDisplayName(context: Context, uri: Uri): String {
    val name = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
    }.getOrNull()
        ?: uri.lastPathSegment
        ?: "file"
    return name.substringAfterLast('/').ifBlank { "file" }
}

/**
 * Copy the bytes behind a content [uri] into a fresh per-item subdirectory of the
 * app cache, preserving the original file name so the recipient sees it. Returns
 * the staged file, or null on failure. The caller deletes the file (and its parent
 * dir) once the send has consumed it.
 */
internal fun stageUriForSend(context: Context, uri: Uri): File? {
    val name = queryDisplayName(context, uri)
    val dir = File(context.cacheDir, "outgoing/${UUID.randomUUID()}").apply { mkdirs() }
    val dest = File(dir, name)
    return try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            dest.outputStream().use { input.copyTo(it) }
        } ?: run {
            dir.deleteRecursively()
            null
        }
        if (dest.exists()) dest else { dir.deleteRecursively(); null }
    } catch (t: Throwable) {
        Log.e("RayfishFiles", "failed to stage $uri for send", t)
        dir.deleteRecursively()
        null
    }
}

/**
 * Auto-accept incoming file offers that come from the user's own paired devices,
 * landing them in Downloads via MediaStore (the same path as a manual "Save").
 *
 * Own-device is decided core-side from the device cert chain (FileOffer.own_device).
 * Gated by the user's opt-out toggle (default on). Idempotent: a process-lived set
 * of accepted ids prevents re-accepting the same offer across the many pollers that
 * call this (the foreground HomeScreen poll and the VpnService background poll).
 *
 * Accepts run on a small bounded pool rather than one raw thread per offer: with two
 * pollers (HomeScreen every 2s, the VPN service every 4s) and no cap, a persistently
 * failing offer would otherwise respawn an unbounded number of concurrent blocking
 * downloads. Retries are also capped per offer id; past [MAX_ATTEMPTS] the id is left
 * in [handled] for good so it stops being retried.
 */
object FileAutoAccept {
    private val handled = java.util.Collections.synchronizedSet(HashSet<ULong>())
    private val attempts = java.util.concurrent.ConcurrentHashMap<ULong, Int>()
    private val executor = java.util.concurrent.Executors.newFixedThreadPool(2) as java.util.concurrent.ThreadPoolExecutor
    private const val MAX_ATTEMPTS = 3

    /** Best-effort: whether an accept is currently running on [executor]. Used only
     * to log plainly when a forced offline teardown (see RayfishVpnService's
     * handleBringUpFailure) is about to drop an in-flight receive; not a signal
     * anything waits on or retries against. */
    fun hasInFlightAccepts(): Boolean = executor.activeCount > 0
    // Ids we have permanently given up retrying. Exposed so HomeScreen can exempt
    // them from the "hide own-device offers while auto-accept is on" filter: once
    // we give up, the offer would otherwise be invisible with no way to save it.
    private val gaveUp = java.util.Collections.synchronizedSet(HashSet<ULong>())

    /** True once auto-accept has permanently given up on this offer id (past
     * MAX_ATTEMPTS). Lets the caller fall back to a manual Save row. */
    fun hasGivenUp(id: ULong): Boolean = id in gaveUp

    /**
     * Clear all process-wide offer-id bookkeeping. The core's file offer ids
     * restart at 1 on the next Node.start(), so a stale entry here would
     * otherwise mute (or, having given up, wrongly un-hide) an offer that
     * happens to reuse an old id. Safe to call when nothing is running.
     */
    fun reset() {
        handled.clear()
        attempts.clear()
        gaveUp.clear()
    }

    /** Runs on the caller's coroutine context; callers dispatch it on IO. */
    fun run(context: Context) {
        if (!NodeHolder.isAutoAcceptOwnDevices(context)) return
        val node = NodeHolder.get(context)
        val offers = runCatching { node.listFileOffers() }.getOrNull() ?: return
        // App-private staging dir; moveToDownloads then relocates to public Downloads.
        val saveDir = context.getExternalFilesDir(null)?.absolutePath ?: context.filesDir.absolutePath
        for (f in offers) {
            if (!f.ownDevice) continue
            if (!handled.add(f.id)) continue
            val key = TransferKey(f.from, f.filename, f.size)
            // Mark the save pending before the blocking accept even starts: the
            // core reports the transfer DONE from inside acceptFileOffer, well
            // before moveToDownloads below has copied a single byte, so a poller
            // racing this thread must see "pending" from the first moment DONE
            // can appear.
            DownloadsOutcome.markPending(key)
            // acceptFileOffer blocks for the whole download; the bounded pool caps
            // how many can run at once regardless of how many offers are pending.
            // The core registers the transfer, so TransferNotifier picks it up.
            executor.execute {
                try {
                    node.acceptFileOffer(f.id, saveDir)
                    val reached = moveToDownloads(context, File(saveDir, f.filename), f.filename, f.mimeType)
                    DownloadsOutcome.record(key, reached)
                    attempts.remove(f.id)
                    Log.i("RayfishFiles", "auto-accepted own-device file ${f.filename}")
                } catch (t: Throwable) {
                    // The accept itself failed: no Downloads outcome is ever coming
                    // for this key, so stop treating it as pending immediately
                    // rather than making the result notification wait out the
                    // timeout for a failure that has already happened.
                    DownloadsOutcome.clearPending(key)
                    val tries = attempts.merge(f.id, 1) { old, inc -> old + inc } ?: 1
                    if (tries < MAX_ATTEMPTS) {
                        // Let a later poll retry this id.
                        handled.remove(f.id)
                        Log.w("RayfishFiles", "auto-accept failed for ${f.filename}, will retry ($tries/$MAX_ATTEMPTS)", t)
                    } else {
                        // Give up: id stays in `handled` so no poller respawns it
                        // again, and is recorded in `gaveUp` so the offer can still
                        // be saved manually instead of vanishing for good.
                        gaveUp.add(f.id)
                        Log.w("RayfishFiles", "auto-accept giving up on ${f.filename} after $tries attempts", t)
                    }
                }
            }
        }
    }
}
