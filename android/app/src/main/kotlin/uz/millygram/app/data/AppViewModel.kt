package uz.millygram.app.data

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uz.millygram.app.DeliveryService
import uz.millygram.protocol.Protocol

/**
 * Owns the session for as long as the process lives.
 *
 * Everything the UI can do that touches the network or the vault goes through
 * here, so there is exactly one place that knows whether an account exists and
 * whether it is unlocked. Screens observe state; they never hold a client.
 */
class AppViewModel(application: Application) : AndroidViewModel(application) {

    sealed interface State {
        /** No vault on this device yet. */
        data object NeedsAccount : State

        /** A vault exists but has not been opened this run. */
        data object Locked : State

        data class Working(val what: String) : State

        data class Ready(val session: MillygramSession) : State

        /** Recoverable: the user can correct the input and try again. */
        data class Failed(val message: String, val previous: State) : State
    }

    private val _state = MutableStateFlow<State>(
        // Reuse a session the process is already holding, so returning to the
        // app after the activity was destroyed does not ask for the passphrase
        // again while the socket is still open behind it.
        SessionHolder.session?.let(State::Ready)
            ?: if (MillygramSession.exists(application)) State.Locked else State.NeedsAccount,
    )
    val state: StateFlow<State> = _state.asStateFlow()

    /** Where the gateway lives. 10.0.2.2 is the emulator's alias for the host. */
    var serverUrl: String = DEFAULT_SERVER
        private set

    /**
     * Where submissions go. The relay forwards a body sealed to the gateway's
     * key, so it learns the sender's address and nothing else, while the
     * gateway learns the envelope and not who sent it. Neither half alone links
     * a sender to a bucket, which is the whole point of running two of them.
     */
    var relayUrl: String = DEFAULT_RELAY
        private set

    fun register(username: String, passphrase: String, server: String, relay: String) {
        if (!Protocol.isValidUsername(username)) {
            _state.value = State.Failed(
                "Foydalanuvchi nomi 3–32 ta belgi boʻlishi kerak: a–z, 0–9 yoki _",
                State.NeedsAccount,
            )
            return
        }
        if (passphrase.length < MIN_PASSPHRASE) {
            _state.value = State.Failed(
                "Parol kamida $MIN_PASSPHRASE ta belgidan iborat boʻlsin",
                State.NeedsAccount,
            )
            return
        }

        serverUrl = server.trim().ifEmpty { DEFAULT_SERVER }
        relayUrl = relay.trim()
        _state.value = State.Working("Hisob yaratilmoqda…")

        viewModelScope.launch {
            runCatching {
                MillygramSession.register(
                    getApplication(),
                    username,
                    passphrase,
                    serverUrl,
                    relayUrl.ifEmpty { null },
                )
            }.onSuccess { session ->
                adopt(session)
                _state.value = State.Ready(session)
            }.onFailure { failure ->
                _state.value = State.Failed(describe(failure), State.NeedsAccount)
            }
        }
    }

    fun unlock(passphrase: String, server: String, relay: String) {
        serverUrl = server.trim().ifEmpty { DEFAULT_SERVER }
        relayUrl = relay.trim()
        _state.value = State.Working("Ochilmoqda…")

        viewModelScope.launch {
            runCatching {
                MillygramSession.open(
                    getApplication(),
                    passphrase,
                    serverUrl,
                    relayUrl.ifEmpty { null },
                )
            }.onSuccess { session ->
                adopt(session)
                _state.value = State.Ready(session)
            }.onFailure {
                // The vault does not distinguish a wrong passphrase from a
                // tampered file, and neither should this message: saying which
                // it was would tell an attacker holding the device whether the
                // passphrase they tried was the shape of the real one.
                _state.value = State.Failed("Parol notoʻgʻri", State.Locked)
            }
        }
    }

    /**
     * Hands the session to the process rather than to this view model, and
     * starts the service that keeps its socket open.
     *
     * The session used to be closed in onCleared, which tied the ability to
     * receive anything to whether an activity happened to exist. It outlives
     * the screen now; what it cannot outlive is the process, because the vault
     * key is derived from a passphrase that is never written down.
     */
    private fun adopt(session: MillygramSession) {
        SessionHolder.adopt(session)
        session.connect()
        DeliveryService.start(getApplication())
    }

    /** Ends the session and the notifications with it. */
    fun signOut() {
        DeliveryService.stop(getApplication())
        SessionHolder.release()
        _state.value = if (MillygramSession.exists(getApplication())) State.Locked else State.NeedsAccount
    }

    fun dismissError() {
        val current = _state.value
        if (current is State.Failed) _state.value = current.previous
    }

    suspend fun send(recipient: String, body: String): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.send(recipient, body) }
    }

    /** Re-sends a message the relay never accepted. */
    suspend fun retry(peerAci: String, messageId: Long): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.retry(peerAci, messageId) }
    }

    /**
     * Turns a failure into something the person holding the phone can act on.
     *
     * The fallback deliberately does not include the underlying message. The
     * gateway speaks in codes like `clock_skew`, and the transport in English
     * exception text; either one landing in the middle of an otherwise Uzbek
     * screen tells the user nothing and can carry internal detail with it.
     */
    private fun describe(failure: Throwable): String {
        val message = failure.message.orEmpty()
        return when {
            "username_taken" in message -> "Bu nom band"
            "not_found" in message -> "Bunday foydalanuvchi topilmadi"
            "slow_down" in message -> "Juda koʻp urinish. Biroz kuting"
            // The device clock, not the server's: registration is refused if
            // they differ by more than five minutes, and a handset that has
            // been flat for a while comes back with the wrong time.
            "clock_skew" in message -> "Qurilma soati notoʻgʻri. Sana va vaqtni tekshiring"
            "work_required" in message -> "Server band. Biroz kutib, qayta urinib koʻring"
            "Failed to connect" in message ||
                "Unable to resolve" in message ||
                "timeout" in message.lowercase() ||
                failure is java.io.IOException -> "Serverga ulanib boʻlmadi"
            else -> "Xatolik yuz berdi. Qayta urinib koʻring"
        }
    }

    /** Same wording, for failures that surface outside the onboarding screen. */
    fun explain(failure: Throwable): String = describe(failure)

    // Deliberately no onCleared teardown. The session belongs to the process
    // now, not to this view model, or closing the screen would stop delivery.

    private companion object {
        /** Set per build type; see the app's build.gradle.kts. */
        val DEFAULT_SERVER: String = uz.millygram.app.BuildConfig.DEFAULT_SERVER
        val DEFAULT_RELAY: String = uz.millygram.app.BuildConfig.DEFAULT_RELAY

        /**
         * The vault key is derived from this, so its length is the real
         * strength of at-rest protection. scrypt makes each guess expensive;
         * it cannot make a four-character passphrase safe.
         */
        const val MIN_PASSPHRASE = 8
    }
}
