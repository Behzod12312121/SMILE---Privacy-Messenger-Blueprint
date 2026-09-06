package uz.millygram.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import uz.millygram.app.data.Arrival
import uz.millygram.app.data.NotificationDetail
import uz.millygram.app.data.SessionHolder

/**
 * Keeps the delivery socket open while the app is not in front.
 *
 * Deliberately not Firebase. Push would mean depending on Google Play services,
 * putting a third party in the path of every message, and handing the gateway a
 * per-account device token — a stable identifier for exactly the thing the
 * bucketed mailboxes exist to avoid knowing. A socket held open costs battery
 * and costs nobody any information.
 *
 * It can only run while the process holds an unlocked session, because the
 * vault key is derived from a passphrase that is never stored. A reboot ends
 * both, and the user unlocks again.
 */
class DeliveryService : Service() {

    private var scope: CoroutineScope? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannels(this)
        startForeground(ONGOING_ID, ongoingNotification())

        val session = SessionHolder.session ?: run {
            stopSelf()
            return
        }

        val started = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        scope = started
        started.launch {
            session.arrivals.collect { arrival -> notifyArrival(arrival, session.notificationDetail) }
        }
    }

    /**
     * Not sticky. Restarting this after the process dies would bring back a
     * service with no session to listen to — the vault key went with the
     * process — so it would start, find nothing, and stop again. The app starts
     * it when someone unlocks, which is the only moment it can do any work.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    override fun onDestroy() {
        scope?.cancel()
        scope = null
        super.onDestroy()
    }

    /**
     * Announces an arrival, saying as much as the user has allowed and no more.
     *
     * A locked phone gets the short version regardless of that setting. That is
     * what publicVersion is for, and it is not configurable: the likeliest
     * adversary for most people is whoever is standing next to them, and this
     * window already keeps itself out of screenshots and the recents thumbnail
     * for the same reason. Once the phone is unlocked, the notification says
     * what was asked for.
     */
    private fun notifyArrival(arrival: Arrival, detail: NotificationDetail) {
        val open = PendingIntent.getActivity(
            this,
            arrival.peerAci.hashCode(),
            Intent(this, MainActivity::class.java)
                .setAction(Intent.ACTION_VIEW)
                .putExtra(EXTRA_CONVERSATION, arrival.peerAci),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val anonymous = getString(R.string.notification_new_message)
        val locked = NotificationCompat.Builder(this, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(anonymous)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()

        val builder = NotificationCompat.Builder(this, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(locked)

        when (detail) {
            NotificationDetail.NameAndMessage -> builder
                .setContentTitle(arrival.username)
                .setContentText(arrival.body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(arrival.body))
            NotificationDetail.NameOnly -> builder
                .setContentTitle(arrival.username)
                .setContentText(getString(R.string.notification_wrote_to_you))
            NotificationDetail.Nothing -> builder.setContentTitle(anonymous)
        }

        // One notification per conversation, so several people writing does not
        // collapse into a single line the way one person writing twice should.
        val id = if (detail == NotificationDetail.Nothing) MESSAGE_ID else arrival.peerAci.hashCode()
        runCatching { NotificationManagerCompat.from(this).notify(id, builder.build()) }
    }

    private fun ongoingNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ONGOING)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(getString(R.string.notification_listening))
            .setOngoing(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()

    companion object {
        private const val CHANNEL_ONGOING = "delivery"
        private const val CHANNEL_MESSAGES = "messages"
        private const val ONGOING_ID = 1
        private const val MESSAGE_ID = 2

        /** Which conversation a tapped notification should open. */
        const val EXTRA_CONVERSATION = "uz.millygram.conversation"

        fun start(context: Context) {
            val intent = Intent(context, DeliveryService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, DeliveryService::class.java))
        }

        /**
         * Clears the notification for a conversation the user is now reading.
         *
         * Without this they pile up until tapped, so opening the app and
         * reading everything leaves a row of announcements about messages
         * already seen.
         */
        fun clearNotification(context: Context, peerAci: String) {
            runCatching {
                NotificationManagerCompat.from(context).cancel(peerAci.hashCode())
            }
        }

        private fun createChannels(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val manager = context.getSystemService(NotificationManager::class.java)

            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ONGOING,
                    context.getString(R.string.channel_delivery),
                    NotificationManager.IMPORTANCE_MIN,
                ).apply { setShowBadge(false) },
            )
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_MESSAGES,
                    context.getString(R.string.channel_messages),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply {
                    setShowBadge(true)
                    // Private, not secret: the notification appears on a
                    // locked screen but shows only its public version, which
                    // says that something arrived and nothing else.
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                },
            )
        }
    }
}
