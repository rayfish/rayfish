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
 */
object FileAutoAccept {
    private val handled = java.util.Collections.synchronizedSet(HashSet<ULong>())

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
            try {
                node.acceptFileOffer(f.id, saveDir)
                moveToDownloads(context, File(saveDir, f.filename), f.filename, f.mimeType)
                Log.i("RayfishFiles", "auto-accepted own-device file ${f.filename}")
            } catch (t: Throwable) {
                // Let a later poll retry this id.
                handled.remove(f.id)
                Log.w("RayfishFiles", "auto-accept failed for ${f.filename}", t)
            }
        }
    }
}
