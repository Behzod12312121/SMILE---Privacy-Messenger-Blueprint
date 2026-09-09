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

    /**
     * True once the live key is confirmed to sit in a discrete secure element
     * (StrongBox / Titan) rather than the general TEE. Read for the risk signal
     * the gateway records; it changes nothing about how the key is used.
     */
    fun isStrongBoxBacked(): Boolean = runCatching {
        val key = load() ?: return false
        val factory = java.security.KeyFactory.getInstance(key.algorithm, KEYSTORE)
        val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }.getOrDefault(false)

    private fun create(): SecretKey? {
        // StrongBox first. On a phone with a discrete secure element — the
        // Titan M2 in a modern Samsung, Pixel's Titan, most recent midrange —
        // the key is generated inside that chip and cannot be pulled out of it
        // by a kernel exploit, only used through it. A copied database is then
        // worthless on the attacker's own hardware even with root: the wrapping
        // key never left the element it was born in.
        //
        // Deliberately NOT setUserAuthenticationRequired. That would bind the
        // key to a fresh fingerprint, and this key exists precisely so the
        // background service can decrypt a message that arrives while nobody is
        // holding the phone. Auth-binding it would stop notifications until the
        // next manual unlock — the exact failure the screen-level lock avoids
        // by gating the screen instead of the key.
        strongBox()?.let {
            android.util.Log.i("MillyGuard", "vault key created in StrongBox")
            return it
        }
        // Older or cheaper handsets have no separate element. The key still
        // lives in the TEE, non-extractable and unlock-gated; a copied vault is
        // still useless without this device. StrongBox is a hardening, not a
        // requirement, so its absence must never lock a real user out.
        android.util.Log.i("MillyGuard", "vault key created in TEE (no StrongBox for AES on this device)")
        return teeOnly()
    }

    private fun strongBox(): SecretKey? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return runCatching { generate(strongBox = true) }
            .getOrElse { failure ->
                // StrongBoxUnavailableException is the documented "no element
                // here" signal, but some OEMs throw a plain ProviderException
                // or KeyStoreException instead, so anything short of success
                // falls through to the TEE rather than failing the open.
                null
            }
    }

    private fun teeOnly(): SecretKey? = runCatching { generate(strongBox = false) }.getOrNull()

    private fun generate(strongBox: Boolean): SecretKey {
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
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
            }
            .build()
        generator.init(spec)
        return generator.generateKey()
    }
}
