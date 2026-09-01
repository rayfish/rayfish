package xyz.rayfish.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import io.sentry.android.core.SentryLogcatAdapter as Log
import uniffi.ray_mobile.FileOffer

/**
 * Notifies about incoming file offers that are waiting for the user to decide.
 *
 * [TransferNotifier] reports *transfers*, and on the receiving side a transfer
 * only exists once the file has been accepted (the core registers it inside
 * `accept_file`). An offer from a peer that is not one of the user's own paired
 * devices is never auto-accepted, so it sits in `listFileOffers()` with no
 * transfer behind it and nothing to report: before this, the only place it
 * surfaced was the HomeScreen row, which is painted only while the app is open.
 * A file sent by another peer therefore arrived in total silence.
 *
 * The notification carries Save and Reject actions handled by [ReceiveService],
 * so the file can be taken without opening the app at all. Driven by the same
 * pollers as [TransferNotifier]: the RayfishVpnService background tick (which
 * runs in standby too) and HomeScreen's foreground loop.
 *
 * Its own channel, at default importance: an offer waiting on the user is the one
 * thing here worth interrupting for, while the transfers channel is deliberately
 * IMPORTANCE_LOW so progress bars stay silent.
 */
object OfferNotifier {
    internal const val CHANNEL_ID = "rayfish_incoming_offers"

    // Its own id range, clear of the VPN (1), SendService (2 and 100+), and
    // TransferNotifier (5000+) ids. Offer ids and transfer ids are independent
    // counters that both start at 1, so the two ranges must not overlap or a
    // transfer would overwrite the offer notification that spawned it.
    private const val NOTIF_BASE = 900_000

    // Offer ids we have posted a notification for. Doubles as the dismissal
    // guard: a poll that finds an id already in here does not notify() again, so
    // a notification the user swiped away stays away instead of being reposted
    // by the next tick a few seconds later.
    private val posted = java.util.Collections.synchronizedSet(HashSet<ULong>())

    // Offers the user has acted on, whose accept or reject is still in flight.
    // The core removes a pending offer only when accept_file actually runs (on
    // ReceiveService's worker thread), so without this a poll landing in that
    // window would see the offer still listed and post it right back over the
    // action the user just took.
    private val acted = java.util.Collections.synchronizedSet(HashSet<ULong>())

    @Volatile private var channelName: String? = null
    private var cancelledStaleOnStart = false

    /**
     * Read the pending offers and reconcile notifications. Safe on any thread.
     *
     * Serialized like [TransferNotifier.poll] and for the same reason: two
     * pollers reading the offer list and writing notifications concurrently can
     * otherwise interleave a cancel from one with a post from the other and
     * leave a notification on screen for an offer that is gone.
     */
    fun poll(context: Context) {
        synchronized(this) {
            // The core's pending offers live in memory and do not survive a
            // process restart, so any offer notification still in the shade at
            // this point names an offer that no longer exists. Worse, offer ids
            // restart at 1, so its Save action could be pointed at a completely
            // different file. Clear them once, before posting anything of ours.
            if (!cancelledStaleOnStart) {
                cancelledStaleOnStart = true
                cancelStaleNotifications(context)
            }

            val offers = runCatching { NodeHolder.get(context).listFileOffers() }.getOrNull() ?: return
            val autoAccepting = NodeHolder.isAutoAcceptOwnDevices(context)
            // The same filter HomeScreen applies to its rows: an own-device offer
            // is FileAutoAccept's to take (and TransferNotifier's to report) until
            // it permanently gives up, at which point the only way to save the
            // file is a manual tap and it needs a notification like any other.
            val waiting = offers.filter {
                !(autoAccepting && it.ownDevice) || FileAutoAccept.hasGivenUp(it.id)
            }
            for (f in waiting) {
                if (f.id in acted) continue
                if (!posted.add(f.id)) continue
                // Written back out if notify() throws, so a later poll retries
                // rather than treating the offer as posted forever and silently
                // muting it.
                if (!runCatching { post(context, f) }.isSuccess) posted.remove(f.id)
            }
            val live = waiting.mapTo(HashSet()) { it.id }
            // Accepted, rejected, or evicted from the core's queue: whatever it
            // said is no longer true, so it must not outlive the offer.
            val nm = context.getSystemService(NotificationManager::class.java)
            for (id in posted.filter { it !in live }) {
                runCatching { nm.cancel(notifId(id)) }
                posted.remove(id)
            }
            acted.removeAll { it !in live }
        }
    }

    /** Cancel every offer notification in our own range on our own channel. Only
     * called once per process, before we have posted anything, so it can only
     * ever reach notifications left behind by a previous process. */
    private fun cancelStaleNotifications(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        runCatching {
            for (sbn in nm.activeNotifications) {
                if (sbn.id < NOTIF_BASE) continue
                if (sbn.notification.channelId == CHANNEL_ID) nm.cancel(sbn.id)
            }
        }
    }

    /**
     * The user has decided on this offer: stop reporting it and take the
     * notification down now rather than at the next poll.
     *
     * Called from every path that acts on an offer, whether from the notification
     * ([ReceiveService]) or from the app's own rows (HomeScreen), so the two can
     * never leave each other's notification standing.
     */
    fun markActedOn(context: Context, id: ULong) {
        synchronized(this) {
            acted.add(id)
            posted.remove(id)
            runCatching {
                context.getSystemService(NotificationManager::class.java).cancel(notifId(id))
            }
        }
    }

    /** The action taken on [id] failed, so the offer may still be pending: stop
     * suppressing it and let the next poll decide again. */
    fun clearActedOn(id: ULong) {
        synchronized(this) { acted.remove(id) }
    }

    /**
     * Reset all bookkeeping and clear what is on screen. Node.stop() drops the
     * core's pending offers and the next start's ids restart at 1, so a stale
     * entry here would mute a later offer that reuses an id, while its
     * notification kept offering to save a file that no longer exists.
     */
    fun reset(context: Context) {
        synchronized(this) {
            val nm = context.getSystemService(NotificationManager::class.java)
            for (id in posted) {
                runCatching { nm.cancel(notifId(id)) }
            }
            posted.clear()
            acted.clear()
            cancelledStaleOnStart = false
        }
    }

    internal fun notifId(id: ULong): Int = NOTIF_BASE + (id.toInt() and 0xffff)

    private fun post(context: Context, f: FileOffer) {
        ensureChannel(context)
        val text = context.getString(R.string.notif_offer_text, f.from, formatSize(f.size))
        val builder = Notification.Builder(context, CHANNEL_ID)
            .setContentTitle(f.filename)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentIntent(
                PendingIntent.getActivity(
                    context,
                    notifId(f.id),
                    Intent(context, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            // Swipe-dismissible on purpose. The offer waits on a human who may
            // never act on it, and an ongoing notification would sit there for
            // good (on older Android, unswipeable) for every file the user has
            // decided to ignore. Dismissing it does not reject the offer; the
            // row in the app is still there.
            .setAutoCancel(true)
            .addAction(
                action(
                    context, f, ReceiveService.ACTION_ACCEPT, context.getString(R.string.action_save),
                    android.R.drawable.stat_sys_download,
                ),
            )
            .addAction(
                action(
                    context, f, ReceiveService.ACTION_REJECT, context.getString(R.string.action_reject),
                    android.R.drawable.ic_menu_close_clear_cancel,
                ),
            )
        context.getSystemService(NotificationManager::class.java)
            .notify(notifId(f.id), builder.build())
        Log.i("RayfishFiles", "offer ${f.id} from ${f.from} (${f.filename}) notified")
    }

    /** One notification action, routed to [ReceiveService].
     *
     * The request code mixes the action in rather than being the offer id alone.
     * Two PendingIntents match on component, action and data but *not* on extras,
     * so Save and Reject stay distinct only because their intent actions differ:
     * a distinct request code means the two buttons cannot collide even if that
     * ever stops being true. */
    private fun action(
        context: Context,
        f: FileOffer,
        action: String,
        label: String,
        iconRes: Int,
    ): Notification.Action {
        val intent = ReceiveService.intent(context, action, f)
        val code = notifId(f.id) * 2 + if (action == ReceiveService.ACTION_ACCEPT) 0 else 1
        // A foreground service cannot normally be started from the background,
        // but tapping a notification action puts the app on the system's
        // temporary allowlist, which is exactly what this exemption is for.
        //
        // FLAG_UPDATE_CURRENT is load-bearing, not tidiness. A PendingIntent is
        // matched on package, request code and `Intent.filterEquals`, which
        // deliberately ignores extras, and the request code here comes from the
        // offer id -- a counter that restarts at 1 in every process. Without the
        // flag, offer 1 of this run reuses the record left in system_server by
        // offer 1 of the last one, so the button says one filename and hands
        // ReceiveService the previous file's name, peer and size.
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val pending = PendingIntent.getForegroundService(context, code, intent, flags)
        val icon = Icon.createWithResource(context, iconRes)
        return Notification.Action.Builder(icon, label, pending).build()
    }

    /** See [TransferNotifier.ensureChannel]: one definition per channel, rewritten
     * only when the localized name changes, and the name is recorded only after
     * the platform actually has the channel or a notify() racing it would be
     * dropped in silence. */
    internal fun ensureChannel(context: Context) {
        val name = context.getString(R.string.notif_channel_offers)
        if (channelName == name) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            name,
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply { description = context.getString(R.string.notif_channel_offers_desc) }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        channelName = name
    }
}
