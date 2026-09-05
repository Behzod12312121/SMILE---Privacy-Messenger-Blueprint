package uz.millygram.protocol

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.SCrypt

/**
 * Encrypt-at-rest primitives for the local vault.
 *
 * Every stored value is bound to its own row identifier through AAD. Without
 * that binding an attacker with write access to the file could take a valid
 * ciphertext from one row and drop it into another — swapping a contact's
 * pinned identity key for a different one, for instance — without ever
 * breaking the cipher. This module is a straight port of the Node
 * implementation in `packages/client/src/store.ts`.
 *
 * scrypt is memory-hard and needs no native build step. Argon2id would be the
 * eventual upgrade; the KDF parameters live inside the vault row, so an
 * existing database can be rewrapped without losing anything.
 */
object Vault {

    const val KEY_BYTES: Int = 32
    const val NONCE_BYTES: Int = 12
    const val TAG_BITS: Int = 128
    const val SALT_BYTES: Int = 16

    /**
     * Parameters chosen to hurt an offline dictionary attacker without hurting
     * a real user.
     *
     * N = 32768 costs about 32 MB of working memory. The obvious 65536 doubles
     * that to 64 MB, which on the entry-level handsets this app is aimed at is
     * a real risk of a slow unlock or an OOM at the worst possible moment —
     * opening the app. 32 MB still forces an attacker to spend that memory for
     * every single guess, which is the property that matters.
     *
     * These values are stored per-database, so raising them later rewraps an
     * existing vault rather than locking anybody out.
     */
    data class KdfParameters(val n: Int = 32_768, val r: Int = 8, val p: Int = 1)

    private val random = SecureRandom()

    fun randomBytes(length: Int): ByteArray {
        val out = ByteArray(length)
        random.nextBytes(out)
        return out
    }

    fun randomSalt(): ByteArray = randomBytes(SALT_BYTES)

    fun randomDataKey(): ByteArray = randomBytes(KEY_BYTES)

    /**
     * Bind a stored value to the exact place it belongs. Relocating a valid
     * ciphertext to a different row therefore breaks authentication rather
     * than succeeding silently.
     */
    fun aad(table: String, key: String): ByteArray =
        "millygram/v1/$table/$key".toByteArray(Charsets.UTF_8)

    fun deriveKey(passphrase: String, salt: ByteArray, params: KdfParameters = KdfParameters()): ByteArray {
        require(salt.size == SALT_BYTES) { "salt must be $SALT_BYTES bytes, got ${salt.size}" }
        return SCrypt.generate(
            passphrase.let(::normalise).toByteArray(Charsets.UTF_8),
            salt,
            params.n,
            params.r,
            params.p,
            KEY_BYTES,
        )
    }

    /** NFKC to match the Node side, so a passphrase entered on any keyboard hashes the same. */
    private fun normalise(value: String): String = java.text.Normalizer.normalize(value, java.text.Normalizer.Form.NFKC)

    /** AES-256-GCM under `key`, committing to `associated`. Layout: 12-byte nonce ‖ 16-byte tag ‖ body. */
    fun seal(key: ByteArray, associated: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "key must be $KEY_BYTES bytes" }
        val nonce = randomBytes(NONCE_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_BITS, nonce),
        )
        cipher.updateAAD(associated)
        val ciphertextWithTag = cipher.doFinal(plaintext)

        val out = ByteArray(NONCE_BYTES + ciphertextWithTag.size)
        nonce.copyInto(out, 0)
        ciphertextWithTag.copyInto(out, NONCE_BYTES)
        return out
    }

    fun open(key: ByteArray, associated: ByteArray, blob: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "key must be $KEY_BYTES bytes" }
        require(blob.size >= NONCE_BYTES + TAG_BITS / 8) { "stored value is truncated" }

        val nonce = blob.copyOfRange(0, NONCE_BYTES)
        val body = blob.copyOfRange(NONCE_BYTES, blob.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_BITS, nonce),
        )
        cipher.updateAAD(associated)
        return cipher.doFinal(body)
    }
}
