package uz.millygram.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import uz.millygram.app.data.MillygramSession
import uz.millygram.app.data.SessionHolder

/**
 * Brings delivery back after a restart, without anyone opening the app.
 *
 * This is the half of "works like every other messenger" that a passphrase made
 * impossible: nothing could decrypt an arriving message until somebody typed it
 * in, so a phone that rebooted overnight was silent until it was picked up and
 * unlocked twice. With the data key held by the device, the first unlock of the
 * phone is enough — the keystore key is unusable while the screen is locked, so
 * this waits for that rather than working around it.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        if (SessionHolder.session != null) return
        if (!MillygramSession.canResume(context)) return

        val app = context.applicationContext
        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                val session = MillygramSession.resume(app, defaultServer(), defaultRelay()) ?: return@launch
                SessionHolder.adopt(session)
                session.connect()
                DeliveryService.start(app)
            } catch (_: Throwable) {
                // A locked screen keeps the key out of reach, which is the
                // intended behaviour rather than a failure. The next launch
                // picks it up.
            } finally {
                pending.finish()
            }
        }
    }

    private fun defaultServer(): String = BuildConfig.DEFAULT_SERVER

    private fun defaultRelay(): String = BuildConfig.DEFAULT_RELAY
}
