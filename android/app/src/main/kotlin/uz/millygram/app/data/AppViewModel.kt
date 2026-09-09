package uz.millygram.app.data

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

        /** A recovery code is in flight to this number and is being waited for. */
        data class CodeSent(val phoneNumber: String) : State

        data class Ready(val session: MillygramSession) : State

        /** Recoverable: the user can correct the input and try again. */
        data class Failed(val message: String, val previous: State) : State
    }

    private val _state = MutableStateFlow<State>(
        // Reuse a session the process is already holding, so returning to the
        // app after the activity was destroyed does not ask for the passphrase
        // again while the socket is still open behind it.
        SessionHolder.session?.let(State::Ready)
            ?: when {
                // Nothing to ask for: the device holds the key. The screen the
                // user saw here was a second passphrase no other messenger asks
                // for, and asking for it every launch is what made the app feel
                // like work.
                MillygramSession.canResume(application) -> State.Working("Ochilmoqda…")
                MillygramSession.exists(application) -> State.Locked
                else -> State.NeedsAccount
            },
    )



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

    init {
        if (SessionHolder.session == null && MillygramSession.canResume(getApplication())) resume()
    }

    /** Opens with the device-held key, falling back to the passphrase screen. */
    private fun resume() {
        viewModelScope.launch {
            // Not adopt(): adopting closes whatever session is already there, and
            // the delivery service may have opened this very vault a moment ago.
            // Resuming asks the holder for the live one and only opens a session
            // when there is none.
            SessionHolder.resumeOrExisting {
                runCatching { MillygramSession.resume(getApplication(), serverUrl, relayUrl.ifEmpty { null }) }
                    .getOrNull()
                    ?.also { it.connect() }
            }
                ?.let { session ->
                    DeliveryService.start(getApplication())
                    _state.value = State.Ready(session)
                }
                ?: run { _state.value = State.Locked }
        }
    }
    val state: StateFlow<State> = _state.asStateFlow()

    fun register(username: String, passphrase: String, server: String, relay: String) {
        if (!Protocol.isValidNickname(username)) {
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

    /**
     * Rebuilds an account from a backup file and opens it.
     *
     * The passphrase is the one the backup was written with, and becomes the
     * passphrase of the restored account — two would be two things to lose.
     */
    fun restore(backup: ByteArray, passphrase: String, server: String, relay: String) {
        serverUrl = server.trim().ifEmpty { DEFAULT_SERVER }
        relayUrl = relay.trim()
        _state.value = State.Working("Tiklanmoqda…")

        viewModelScope.launch {
            runCatching {
                MillygramSession.restore(
                    getApplication(),
                    backup,
                    passphrase,
                    serverUrl,
                    relayUrl.ifEmpty { null },
                )
            }.onSuccess { session ->
                adopt(session)
                _state.value = State.Ready(session)
            }.onFailure { failure ->
                _state.value = State.Failed(describeRestore(failure), State.NeedsAccount)
            }
        }
    }

    private fun describeRestore(failure: Throwable): String {
        val message = failure.message.orEmpty()
        return when {
            "wrong passphrase" in message -> "Parol notoʻgʻri"
            "already holds an account" in message ->
                "Bu qurilmada allaqachon hisob bor. Avval uni oʻchiring"
            "not a MillyGram backup" in message -> "Bu Smile zaxira fayli emas"
            else -> describe(failure)
        }
    }

    /**
     * Asks the gateway to text a recovery code.
     *
     * Deliberately advances to the code screen whatever the gateway says short
     * of a hard failure, because the gateway answers the same way for a number
     * it knows and one it does not. Reporting "no such number" here would turn
     * this route into a way to ask whether a given person uses MillyGram, which
     * in this country is a question with consequences.
     */
    fun startRecovery(phoneNumber: String, server: String, relay: String) {
        val number = phoneNumber.filter { it.isDigit() || it == '+' }
        if (!Protocol.isValidPhoneNumber(number)) {
            _state.value = State.Failed(
                "Raqamni xalqaro shaklda kiriting, masalan +998901234567",
                State.NeedsAccount,
            )
            return
        }

        serverUrl = server.trim().ifEmpty { DEFAULT_SERVER }
        relayUrl = relay.trim()
        _state.value = State.Working("Kod yuborilmoqda…")

        viewModelScope.launch {
            runCatching { MillygramSession.startRecovery(serverUrl, number) }
                .onSuccess { _state.value = State.CodeSent(number) }
                .onFailure { _state.value = State.Failed(describe(it), State.NeedsAccount) }
        }
    }

    /**
     * Finishes a recovery: new keys, old handle, no history.
     *
     * On failure it returns to the code screen rather than the start, since the
     * common case is a mistyped six digits and the code is still valid.
     */
    fun recover(phoneNumber: String, code: String, passphrase: String) {
        if (passphrase.length < MIN_PASSPHRASE) {
            _state.value = State.Failed(
                "Parol kamida $MIN_PASSPHRASE ta belgidan iborat boʻlsin",
                State.CodeSent(phoneNumber),
            )
            return
        }

        _state.value = State.Working("Hisob tiklanmoqda…")
        viewModelScope.launch {
            runCatching {
                MillygramSession.recover(
                    getApplication(),
                    phoneNumber,
                    code.trim(),
                    passphrase,
                    serverUrl,
                    relayUrl.ifEmpty { null },
                )
            }.onSuccess { session ->
                adopt(session)
                _state.value = State.Ready(session)
            }.onFailure { failure ->
                _state.value = State.Failed(describeRecovery(failure), State.CodeSent(phoneNumber))
            }
        }
    }

    /** Abandons a recovery in progress, back to the first screen. */
    fun cancelRecovery() {
        if (_state.value is State.CodeSent) _state.value = State.NeedsAccount
    }

    private fun describeRecovery(failure: Throwable): String {
        val message = failure.message.orEmpty()
        return when {
            // The gateway answers 401 for a wrong code and 404 for a number it
            // has never seen. Both are shown as one message on purpose: telling
            // them apart is the enumeration leak the start route avoids, and it
            // would be pointless to close it there and open it here.
            "bad_code" in message || "not_found" in message ->
                "Kod notoʻgʻri yoki muddati oʻtgan"
            "already holds an account" in message ->
                "Bu qurilmada allaqachon hisob bor. Avval uni oʻchiring"
            else -> describe(failure)
        }
    }

    fun unlock(passphrase: String, server: String, relay: String) {
        serverUrl = server.trim().ifEmpty { DEFAULT_SERVER }
        relayUrl = relay.trim()

        viewModelScope.launch {
            val wait = withContext(Dispatchers.IO) { remainingPenaltyMs() }
            if (wait > 0) {
                _state.value = State.Failed(
                    "Juda koʻp urinish. ${describeWait(wait)}dan keyin qayta urining",
                    State.Locked,
                )
                return@launch
            }

            _state.value = State.Working("Ochilmoqda…")
            runCatching {
                MillygramSession.open(
                    getApplication(),
                    passphrase,
                    serverUrl,
                    relayUrl.ifEmpty { null },
                )
            }.onSuccess { session ->
                withContext(Dispatchers.IO) { clearFailedAttempts() }
                adopt(session)
                _state.value = State.Ready(session)
            }.onFailure {
                val penalty = withContext(Dispatchers.IO) { recordFailedAttempt() }
                // The vault does not distinguish a wrong passphrase from a
                // tampered file, and neither should this message: saying which
                // it was would tell an attacker holding the device whether the
                // passphrase they tried was the shape of the real one.
                _state.value = State.Failed(
                    if (penalty == 0L) {
                        "Parol notoʻgʻri"
                    } else {
                        "Parol notoʻgʻri. Keyingi urinishgacha ${describeWait(penalty)}"
                    },
                    State.Locked,
                )
            }
        }
    }

    /**
     * The count of consecutive wrong passphrases, kept outside the vault.
     *
     * It has to live somewhere readable before the vault opens, which rules out
     * the vault itself — the counter's whole job is to be consulted while the
     * only thing the attacker has produced so far is a failed open. So it is an
     * ordinary private preferences file, and it is worth being honest about what
     * that means: somebody with root, or with adb on a debuggable build, can
     * delete it and start counting from zero again. This is not the defence
     * against that person. It is the defence against the far commoner one —
     * whoever is holding the phone, working through birthdays and the name of
     * the street, or a script doing the same thing faster.
     *
     * scrypt already makes each guess cost real work. What it does not do is
     * make the tenth guess cost more than the first, and that is what the
     * growing delay adds. Nothing here is stored that identifies the account:
     * a count and a timestamp, which say only that somebody got it wrong.
     */
    private val attempts by lazy {
        getApplication<Application>().getSharedPreferences(ATTEMPT_PREFS, Context.MODE_PRIVATE)
    }

    /**
     * How much longer the next attempt has to wait, in milliseconds.
     *
     * A clock that has moved backwards since the last failure is treated as if
     * the wait had only just started rather than as if it were over. Winding the
     * date back is the first thing anyone tries against a delay measured in wall
     * time, and the alternative — a monotonic clock — resets on every reboot,
     * which is even easier to arrange.
     */
    private fun remainingPenaltyMs(): Long {
        val failures = attempts.getInt(ATTEMPT_COUNT, 0)
        val penalty = penaltyMsFor(failures)
        if (penalty == 0L) return 0

        val last = attempts.getLong(ATTEMPT_LAST, 0L)
        val now = System.currentTimeMillis()
        if (now < last) {
            attempts.edit().putLong(ATTEMPT_LAST, now).apply()
            return penalty
        }
        return (last + penalty - now).coerceAtLeast(0)
    }

    /** Counts a wrong passphrase and returns the wait it has just bought. */
    private fun recordFailedAttempt(): Long {
        val failures = attempts.getInt(ATTEMPT_COUNT, 0) + 1
        attempts.edit()
            .putInt(ATTEMPT_COUNT, failures)
            .putLong(ATTEMPT_LAST, System.currentTimeMillis())
            .apply()
        return penaltyMsFor(failures)
    }

    /** The right passphrase clears the record; nothing is held against the owner. */
    private fun clearFailedAttempts() {
        attempts.edit().clear().apply()
    }

    private fun describeWait(millis: Long): String {
        val seconds = (millis + 999) / 1000
        return if (seconds < 60) "$seconds soniya" else "${(seconds + 59) / 60} daqiqa"
    }

    /**
     * Closes the session, stops delivery, and takes away the device's standing
     * permission to open the vault again by itself.
     *
     * The last part is what makes this a lock rather than a gesture. Releasing
     * the session zeroes the data key in memory, but the keystore-wrapped copy
     * on disk survived it, so the next launch simply opened the vault again with
     * no passphrase and no fingerprint — press Lock, swipe the app out of
     * recents, tap the icon, and everything was back. Somebody who reaches for
     * this row is doing it because they are about to hand the phone to a person
     * they cannot refuse, and for them a lock that reopens on the next tap is
     * worse than no lock at all, because they walk away believing it held.
     *
     * The account is untouched — this locks it, it does not leave it. The
     * passphrase still opens it, and opening it that way arms the device key
     * again, so this costs the user exactly one typing and then the app goes
     * back to launching without asking.
     *
     * It runs off the main thread because forgetting touches SQLite and the
     * keystore, and it refuses to claim success it did not get: if the wrapping
     * could not be destroyed the session stays up and the failure is shown,
     * rather than a locked screen over a vault the device can still open.
     */
    fun lock() {
        val previous = _state.value
        _state.value = State.Working("Qulflanmoqda…")

        viewModelScope.launch {
            DeliveryService.stop(getApplication())

            val forgotten = withContext(Dispatchers.IO) {
                runCatching {
                    MillygramSession.forgetDeviceKey(getApplication())
                    // Asked, not assumed. Forgetting swallows its own failures
                    // by design — a keystore entry that was never there is not
                    // an error — so the only honest way to know the shortcut is
                    // gone is to go and look for it. This is the check that
                    // stands between the user and a lock screen drawn over a
                    // vault the phone can still open by itself.
                    check(!MillygramSession.canResume(getApplication())) {
                        "the device can still open the vault"
                    }
                }
            }

            if (forgotten.isFailure) {
                // Delivery was already stopped, so it goes back up: the state
                // being reported is "still open", and it has to be true of the
                // notifications as well as of the session.
                DeliveryService.start(getApplication())
                _state.value = State.Failed(
                    "Qulflab boʻlmadi. Suhbatlar ochiq qoldi, qayta urinib koʻring",
                    previous,
                )
                return@launch
            }

            SessionHolder.release()
            _state.value =
                if (MillygramSession.exists(getApplication())) State.Locked else State.NeedsAccount
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

    fun dismissError() {
        val current = _state.value
        if (current is State.Failed) _state.value = current.previous
    }

    suspend fun send(recipient: String, body: String): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.send(recipient, body) }
    }

    /**
     * Sends to a group, which is a fan-out of ordinary private sends.
     *
     * Separate from [send] because the destination is not a recipient: there is
     * no address for a group, only a list of members the client sends to one at
     * a time. Routing a group body through [send] would deliver it to whoever
     * the thread key happened to name.
     */
    suspend fun sendToGroup(groupId: String, body: String): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.sendToGroup(groupId, body) }
    }

    suspend fun createGroup(name: String, members: List<String>): Result<String> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.createGroup(name, members) }
    }

    suspend fun setGroupMembers(groupId: String, members: List<String>): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.setGroupMembers(groupId, members) }
    }

    suspend fun leaveGroup(groupId: String): Result<Unit> {
        val session = (_state.value as? State.Ready)?.session
            ?: return Result.failure(IllegalStateException("no session"))
        return runCatching { session.leaveGroup(groupId) }
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
    private fun describe(failure: Throwable): String = describeGatewayFailure(failure)

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

        private const val ATTEMPT_PREFS = "unlock-attempts"
        private const val ATTEMPT_COUNT = "consecutive"
        private const val ATTEMPT_LAST = "lastAt"

        /**
         * Two mistypes cost nothing.
         *
         * That number is chosen for the owner, not the attacker. A passphrase
         * long enough to be worth having is a passphrase that gets fat-fingered
         * on a phone keyboard, and somebody who has just been asked for it while
         * standing in the street should not be shut out of their own messages
         * for getting it wrong twice. Everything after that doubles — five
         * seconds, ten, twenty — which a person barely notices and a script
         * cannot outrun, because the wait is what it is regardless of how fast
         * the guesses arrive.
         *
         * The cap is five minutes rather than an hour on purpose. An hour reads
         * as security and is really a way to lose the account: the person most
         * likely to hit the ceiling is the owner on a bad day, and a messenger
         * they cannot get into for an hour is a messenger they go back to
         * Telegram from. Twelve guesses an hour against scrypt is already a
         * number no wordlist survives.
         */
        private const val FREE_ATTEMPTS = 2
        private const val BASE_PENALTY_MS = 5_000L
        private const val MAX_PENALTY_MS = 5 * 60_000L

        private fun penaltyMsFor(failures: Int): Long {
            if (failures <= FREE_ATTEMPTS) return 0
            // Clamped before the shift rather than after: a counter left to run
            // for long enough would otherwise shift past the width of a Long and
            // wrap round to no delay at all, which is the one outcome this must
            // never produce.
            val steps = (failures - FREE_ATTEMPTS - 1).coerceAtMost(16)
            return (BASE_PENALTY_MS shl steps).coerceAtMost(MAX_PENALTY_MS)
        }
    }
}
