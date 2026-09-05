package uz.millygram.app.data

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
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
        if (MillygramSession.exists(application)) State.Locked else State.NeedsAccount,
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
                session.connect()
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
                session.connect()
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

    private fun describe(failure: Throwable): String = when {
        failure.message?.contains("username_taken") == true -> "Bu nom band"
        failure.message?.contains("slow_down") == true -> "Juda koʻp urinish. Biroz kuting"
        failure.message?.contains("Failed to connect") == true ||
            failure.message?.contains("Unable to resolve") == true -> "Serverga ulanib boʻlmadi"
        else -> failure.message ?: "Nomaʼlum xato"
    }

    override fun onCleared() {
        (_state.value as? State.Ready)?.session?.close()
        super.onCleared()
    }

    private companion object {
        const val DEFAULT_SERVER = "http://10.0.2.2:8443"
        const val DEFAULT_RELAY = "http://10.0.2.2:8444"

        /**
         * The vault key is derived from this, so its length is the real
         * strength of at-rest protection. scrypt makes each guess expensive;
         * it cannot make a four-character passphrase safe.
         */
        const val MIN_PASSPHRASE = 8
    }
}
