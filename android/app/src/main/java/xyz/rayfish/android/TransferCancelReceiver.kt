package xyz.rayfish.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Handles Cancel on an outgoing transfer notification. */
class TransferCancelReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val id = intent.getLongExtra(EXTRA_ID, -1L)
        if (id < 0) return
        goAsync().let { pending ->
            Thread {
                runCatching { NodeHolder.get(context).cancelTransfer(id.toULong()) }
                FileStatusMonitor.request()
                pending.finish()
            }.start()
        }
    }

    companion object {
        const val EXTRA_ID = "xyz.rayfish.android.TRANSFER_ID"
    }
}
