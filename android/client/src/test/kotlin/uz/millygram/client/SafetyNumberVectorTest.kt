package uz.millygram.client

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator

/**
 * The number two people read to each other to check that nobody is in the
 * middle of their conversation.
 *
 * Both implementations must derive the same digits from the same pair of
 * identities. Nothing was checking that they did, and a mismatch would have two
 * honest people concluding they were under attack — the exact opposite of what
 * the number is for. The vault layouts had already drifted this way without
 * anything noticing.
 */
class SafetyNumberVectorTest {

    private val vectors: JSONObject by lazy {
        val file = File("src/test/resources/vectors.json")
        JSONObject(file.readText())
    }

    private fun unhex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `the safety number matches the reference implementation`() {
        val vector = vectors.getJSONObject("safetyNumber")

        val generator = NumericFingerprintGenerator(5200)
        val fingerprint = generator.createFor(
            2,
            vector.getString("localAci").toByteArray(Charsets.UTF_8),
            IdentityKey(unhex(vector.getString("localIdentityHex")), 0),
            vector.getString("remoteAci").toByteArray(Charsets.UTF_8),
            IdentityKey(unhex(vector.getString("remoteIdentityHex")), 0),
        )

        assertEquals(vector.getString("digits"), fingerprint.displayableFingerprint.displayText)
    }
}
