package uz.millygram.app.data

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The one place the unlocked session lives.
 *
 * It used to belong to the view model, which meant it died with the activity —
 * fine while nothing needed it in the background, and useless once something
 * does. The vault is opened with a passphrase that is never stored, so this
 * reference is the only thing in the process that can read an arriving
 * message; when the process goes, so does the ability to decrypt, and the user
 * has to unlock again.
 *
 * That is a deliberate consequence of not keeping the key anywhere, not an
 * oversight. Surviving a reboot would mean wrapping the data key with a
 * hardware-backed Keystore key, which is a different bargain than the one this
 * app currently makes.
 */
object SessionHolder {

    private val mutex = Mutex()

    @Volatile
    var session: MillygramSession? = null
        private set

    /**
     * Serialises opening, so only one session is ever built for one vault.
     *
     * Two things resume independently — the view model when a screen appears,
     * and the delivery service when it starts — and both used to check this
     * holder, find it empty, and open a session of their own. Whichever adopted
     * second closed the other one, and since closing a session closes the SQLite
     * database under it, whoever still held the loser crashed the moment it read
     * anything: `attempt to re-open an already-closed object`, fatal, on every
     * launch of an account that can resume without a passphrase.
     *
     * A check followed by a create is not atomic across coroutines. This makes it
     * so: the check, the create and the store all happen under one lock, so the
     * second caller waits and then gets the session the first one made.
     */
    suspend fun resumeOrExisting(open: suspend () -> MillygramSession?): MillygramSession? =
        mutex.withLock {
            session ?: open()?.also { session = it }
        }

    /**
     * Replaces the session outright, closing whatever was there.
     *
     * For the paths that deliberately produce a different account — registering,
     * restoring, recovering, unlocking with a passphrase. Resuming must not come
     * through here: it is not making a new account, and closing a live session is
     * exactly the bug above.
     */
    fun adopt(session: MillygramSession) {
        this.session?.takeIf { it !== session }?.close()
        this.session = session
    }

    fun release() {
        session?.close()
        session = null
    }
}
