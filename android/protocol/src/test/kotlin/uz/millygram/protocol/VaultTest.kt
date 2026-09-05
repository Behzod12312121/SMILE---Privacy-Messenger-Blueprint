package uz.millygram.protocol

import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VaultTest {

    private val message = "a message worth protecting".toByteArray()

    @Test
    fun `seal and open round-trip`() {
        val key = Vault.randomDataKey()
        val aad = Vault.aad("meta", "identity")
        assertContentEquals(message, Vault.open(key, aad, Vault.seal(key, aad, message)))
    }

    @Test
    fun `same plaintext seals to different ciphertext`() {
        val key = Vault.randomDataKey()
        val aad = Vault.aad("meta", "identity")
        val first = Vault.seal(key, aad, message)
        val second = Vault.seal(key, aad, message)
        assertNotEquals(first.toList(), second.toList(), "the nonce must be fresh every time")
    }

    @Test
    fun `the wrong key rejects a valid blob`() {
        val aad = Vault.aad("meta", "identity")
        val sealed = Vault.seal(Vault.randomDataKey(), aad, message)
        assertFailsWith<AEADBadTagException> {
            Vault.open(Vault.randomDataKey(), aad, sealed)
        }
    }

    @Test
    fun `a stored value cannot be relocated to a different row`() {
        val key = Vault.randomDataKey()
        val sealed = Vault.seal(key, Vault.aad("meta", "harmless_value"), message)
        // Attempt to reuse the ciphertext under a different logical name — the
        // exact tampering shape a database write attacker would try.
        assertFailsWith<AEADBadTagException> {
            Vault.open(key, Vault.aad("meta", "identity_pin"), sealed)
        }
    }

    @Test
    fun `flipping a byte of the ciphertext is rejected`() {
        val key = Vault.randomDataKey()
        val aad = Vault.aad("meta", "identity")
        val sealed = Vault.seal(key, aad, message).copyOf()
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()

        assertFailsWith<AEADBadTagException> { Vault.open(key, aad, sealed) }
    }

    @Test
    fun `key derivation is deterministic for the same passphrase and salt`() {
        val salt = ByteArray(Vault.SALT_BYTES) { it.toByte() }
        // Small parameters — this is a determinism test, not a performance test.
        val params = Vault.KdfParameters(n = 1024, r = 8, p = 1)
        val a = Vault.deriveKey("correct horse battery staple", salt, params)
        val b = Vault.deriveKey("correct horse battery staple", salt, params)
        val c = Vault.deriveKey("wrong horse battery staple", salt, params)

        assertContentEquals(a, b)
        assertNotEquals(a.toList(), c.toList())
        assertTrue(a.size == Vault.KEY_BYTES)
    }

    @Test
    fun `nfkc normalisation makes visually identical passphrases match`() {
        val salt = ByteArray(Vault.SALT_BYTES)
        val params = Vault.KdfParameters(n = 1024, r = 8, p = 1)
        // Precomposed é (U+00E9) vs. e + combining acute (U+0065 U+0301). Both
        // render the same, so both must produce the same key.
        val composed = Vault.deriveKey("café", salt, params)
        val decomposed = Vault.deriveKey("café", salt, params)
        assertContentEquals(composed, decomposed)
    }
}
