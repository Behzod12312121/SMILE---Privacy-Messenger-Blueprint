package uz.millygram.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import uz.millygram.app.data.MillygramSession
import uz.millygram.app.data.SessionHolder

/**
 * Brings delivery back after a restart, without anyone opening the app.
 *
 * This is the half of "works like every other messenger" that a passphrase made
 * impossible: nothing could decrypt an arriving message until somebody typed it
 * in, so a phone that rebooted overnight stayed silent until it was picked up.
 *
 * It does nothing but start the service, deliberately. The first version opened
 * the vault and connected here, inside goAsync, and then started the service
 * once that finished — which is the shape Android restricts twice over. A
 * receiver has about ten seconds before the process can be frozen, and this one
 * was: the logs read "freezing uz.millygram" eleven seconds in, with no service
 * ever started. Starting a foreground service from the background is also only
 * permitted while a boot broadcast is actually being handled, which by then it
 * no longer was. The service has its own lifetime and does the waiting.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        if (SessionHolder.session != null) return
        // Nothing to resume without a key this device can use, and asking for a
        // passphrase is not something a broadcast can do.
        if (!MillygramSession.canResume(context)) return

        DeliveryService.start(context.applicationContext)
    }
}
