package uz.millygram.app.data

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
    @Volatile
    var session: MillygramSession? = null
        private set

    fun adopt(session: MillygramSession) {
        this.session?.takeIf { it !== session }?.close()
        this.session = session
    }

    fun release() {
        session?.close()
        session = null
    }
}
