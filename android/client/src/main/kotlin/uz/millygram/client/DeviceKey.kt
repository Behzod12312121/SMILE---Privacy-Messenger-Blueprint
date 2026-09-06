package uz.millygram.client

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * A key held by the device rather than derived from anything the user types.
 *
 * It exists so the app can open without asking for a passphrase every time,
 * which is what people expect and what they get from every other messenger
 * they have used. The trade is explicit: brute-force resistance moves off the
 * CPU cost of scrypt and onto the phone's own lock screen and, where the
 * hardware provides one, its secure element. Someone holding an unlocked handset
 * can read the conversations — which was already true of every messenger the
 * intended users have, and was not true of this one only because it asked for a
 * second passphrase nobody else asks for.
 *
 * What the key cannot do is leave. It is generated inside the keystore and is
 * not extractable, so a copy of the database is worth nothing on another
 * device — the passphrase-wrapped copy of the same data key remains the only
 * way to move an account, and that is what backups use.
 *
 * setUnlockedDeviceRequired means it is unusable while the screen is locked, so
 * a background service can decrypt an arriving message after the user has
 * unlocked their phone once, and not before.
 */
internal object DeviceKey {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "millygram.vault.v1"
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128

    /** True when the phone has a screen lock, which this key requires. */
    fun isAvailable(): Boolean = runCatching { load() ?: create() }.getOrNull() != null

    fun wrap(dataKey: ByteArray): ByteArray? = runCatching {
        val key = load() ?: create() ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val sealed = cipher.doFinal(dataKey)
        cipher.iv + sealed
    }.getOrNull()

    fun unwrap(wrapped: ByteArray): ByteArray? = runCatching {
        if (wrapped.size <= NONCE_BYTES) return null
        val key = load() ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(TAG_BITS, wrapped, 0, NONCE_BYTES),
        )
        cipher.doFinal(wrapped, NONCE_BYTES, wrapped.size - NONCE_BYTES)
    }.getOrNull()

    /** Drops the key, so nothing on this device can open the vault without the passphrase. */
    fun forget() {
        runCatching { KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS) }
    }

    private fun load(): SecretKey? = runCatching {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        store.getKey(ALIAS, null) as? SecretKey
    }.getOrNull()

    private fun create(): SecretKey? = runCatching {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply {
                // Unusable while the screen is locked. A message arriving
                // overnight is decrypted when the phone is next unlocked, not
                // while it sits on a table.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) setInvalidatedByBiometricEnrollment(false)
            }
            .build()
        generator.init(spec)
        generator.generateKey()
    }.getOrNull()
}
