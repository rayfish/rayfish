package xyz.rayfish.android.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ray_mobile.FileOffer
import uniffi.ray_mobile.NetworkConnState
import uniffi.ray_mobile.PendingRequest
import uniffi.ray_mobile.QueuedSend
import uniffi.ray_mobile.Status
import uniffi.ray_mobile.Transfer
import uniffi.ray_mobile.TransferState
import xyz.rayfish.android.DownloadsOutcome
import xyz.rayfish.android.FileAutoAccept
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.OfferNotifier
import xyz.rayfish.android.TransferKey
import xyz.rayfish.android.TransferNotifier

/** One foreground read supplies every tab; failed reads keep the last known data. */
data class AppSnapshot(
    val status: Status? = null,
    val controlPlaneRunning: Boolean = false,
    val files: List<FileOffer> = emptyList(),
    val connects: List<PendingRequest> = emptyList(),
    val joins: List<Pair<String, PendingRequest>> = emptyList(),
    val queued: List<QueuedSend> = emptyList(),
    val transfers: List<Transfer> = emptyList(),
    val savingTransfers: Set<ULong> = emptySet(),
    val loaded: Boolean = false,
    val refreshFailed: Boolean = false,
)

/** Serialize refreshes and coalesce requests made while the native reader is busy. */
internal class SnapshotRefresh(scope: CoroutineScope, read: suspend (AppSnapshot) -> AppSnapshot) {
    private val requests = Channel<Unit>(Channel.CONFLATED)
    private val current = MutableStateFlow(AppSnapshot())
    val state = current.asStateFlow()

    init {
        scope.launch {
            for (request in requests) {
                val previous = current.value
                current.value = try { read(previous) }
                catch (t: CancellationException) { throw t }
                catch (t: Exception) { previous.copy(loaded = true, refreshFailed = true) }
            }
        }
    }

    fun request() { requests.trySend(Unit) }
}

class RayfishViewModel(application: Application) : AndroidViewModel(application) {
    private val refresh = SnapshotRefresh(viewModelScope) { previous ->
        withContext(Dispatchers.IO) { readSnapshot(application, previous) }
    }
    val state = refresh.state
    fun refresh() { refresh.request() }
}

private fun readSnapshot(context: Context, previous: AppSnapshot): AppSnapshot {
    val node = NodeHolder.get(context)
    var failed = false
    fun <T> read(fallback: T, call: () -> T): T = try { call() }
    catch (t: CancellationException) { throw t }
    catch (t: Exception) { failed = true; fallback }

    val status = read(previous.status) { node.status() }
    if (!NodeHolder.isStarted()) return AppSnapshot(status = status, loaded = true, refreshFailed = failed)

    // These are also event driven in the service. Foreground reconciliation covers
    // file-only operation when the user opted out of a standing VPN service.
    runCatching { FileAutoAccept.run(context) }
    runCatching { TransferNotifier.poll(context) }
    runCatching { OfferNotifier.poll(context) }
    val autoAccept = NodeHolder.isAutoAcceptOwnDevices(context)
    val files = read(previous.files) { node.listFileOffers() }
        .filter { !(autoAccept && it.ownDevice) || FileAutoAccept.hasGivenUp(it.id) }
    val transfers = read(previous.transfers) { node.listTransfers() }
    val joins = status?.networks.orEmpty()
        .filter { it.isCoordinator && it.state == NetworkConnState.CONNECTED }
        .flatMap { network ->
            read(previous.joins.filter { it.first == network.name }.map { it.second }) {
                node.listJoinRequests(network.name)
            }.map { network.name to it }
        }
    return AppSnapshot(
        status = status, controlPlaneRunning = true, files = files, joins = joins,
        connects = read(previous.connects) { node.listConnectRequests() },
        queued = read(previous.queued) { node.listQueuedSends() },
        transfers = transfers,
        savingTransfers = transfers.filter {
            !it.outgoing && it.state == TransferState.DONE &&
                DownloadsOutcome.isPending(TransferKey(it.peer, it.filename, it.size))
        }.map { it.id }.toSet(),
        loaded = true, refreshFailed = failed,
    )
}
