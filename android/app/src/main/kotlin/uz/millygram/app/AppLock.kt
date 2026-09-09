package uz.millygram.app

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * The fingerprint gate in front of the conversations.
 *
 * What it is for, precisely: this app already opens without a passphrase,
 * because the vault key is wrapped by a keystore key that works whenever the
 * phone is unlocked. That is what people expect from a messenger, and it leaves
 * one hole — anybody holding your unlocked phone can read everything. Handing
 * someone your phone is an ordinary thing to do, and in this market being asked
 * to unlock it is not always a request you can refuse. This closes that.
 *
 * What it deliberately is NOT: the thing that holds the key. The vault is
 * opened by the passphrase or by the device key, never by a fingerprint, and
 * that is a decision worth defending on two counts.
 *
 * The first is delivery. If the data key needed a fingerprint, then after the
 * process died — a reboot, or the system reclaiming memory overnight — nothing
 * could decrypt an arriving message until the user next opened the app and
 * pressed a finger to the sensor. A messenger that stops receiving while you
 * are not looking at it is broken.
 *
 * The second is loss. Biometrics are not recoverable. A re-enrolled fingerprint
 * or a failed sensor would take the account with it, and this app already tells
 * people plainly that the passphrase is the only way back in. Adding a second
 * thing that can be lost, and losing the account with it, is the opposite of
 * what a recovery story should do.
 *
 * So the honest description of the protection: it stops somebody who can tap
 * the screen. It does not stop somebody who can run code on the device, because
 * the delivery service can still open the vault — it has to, or notifications
 * would not work. Anyone whose threat model includes an attacker with code
 * execution on their unlocked handset should be using the lock in Settings, not
 * this. That one closes the session and then destroys the device's wrapped copy
 * of the vault key, so nothing on the handset can open the account again until
 * the passphrase is typed — which is the difference between a screen in front of
 * the conversations and the conversations actually being shut.
 */
object AppLock {

    /** Why the lock cannot be offered, when it cannot. */
    enum class Availability {
        /** A fingerprint or face is enrolled and usable. */
        Ready,

        /** The hardware exists but nothing is enrolled yet. */
        NotEnrolled,

        /** No usable biometric hardware on this device. */
        Unsupported,
    }

    fun availability(context: Context): Availability {
        val manager = BiometricManager.from(context)
        // DEVICE_CREDENTIAL is included so a phone with no fingerprint sensor
        // can still use its PIN. Excluding it would make this a feature only
        // newer handsets get, on a market full of older ones.
        val allowed = BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return when (manager.canAuthenticate(allowed)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.Ready
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NotEnrolled
            else -> Availability.Unsupported
        }
    }

    /** What happened when the user was asked. */
    sealed interface Outcome {
        data object Passed : Outcome

        /** They cancelled or backed out. The screen stays locked. */
        data object Dismissed : Outcome

        /**
         * The prompt could not run at all — no enrolment, hardware gone, or the
         * sensor locked out after too many attempts. The caller must not treat
         * this as a pass, and must leave the user a way through.
         */
        data class Unavailable(val reason: String) : Outcome
    }

    suspend fun prompt(activity: FragmentActivity): Outcome = suspendCancellableCoroutine { cont ->
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(Outcome.Passed)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (!cont.isActive) return
                    // A wrong finger is not an error — the prompt handles that
                    // itself and keeps asking. These are the cases where it has
                    // stopped asking, and only some of them are the user's
                    // choice.
                    val outcome = when (code) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED,
                        -> Outcome.Dismissed

                        else -> Outcome.Unavailable(message.toString())
                    }
                    cont.resume(outcome)
                }

                // onAuthenticationFailed is deliberately not overridden. It
                // fires on every unrecognised finger, and the prompt is still
                // waiting; resuming here would let one bad read past the gate.
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Smile")
            .setSubtitle("Suhbatlarni ochish uchun tasdiqlang")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_WEAK or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()

        runCatching { prompt.authenticate(info) }
            .onFailure { if (cont.isActive) cont.resume(Outcome.Unavailable(it.message.orEmpty())) }

        cont.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
    }
}
