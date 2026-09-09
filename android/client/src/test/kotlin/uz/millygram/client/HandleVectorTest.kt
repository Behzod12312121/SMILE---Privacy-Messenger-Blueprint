package uz.millygram.client

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.json.JSONObject

/**
 * Handles, against the reference implementation.
 *
 * Both sides call the same Rust code through libsignal, so in principle these
 * cannot disagree. In practice "the same library" is an assumption that stops
 * holding the moment the two versions drift apart, and the failure it produces
 * is the quietest one this project has: a lookup that returns nothing, read by
 * the person doing it as "no such user" rather than as a bug.
 *
 * The proof case is the one worth having. A hash is deterministic and easy to
 * agree on; the proof is where the zero-knowledge machinery lives, and it is
 * generated on the TypeScript side and verified here, which is the direction a
 * real registration travels.
 */
class HandleVectorTest {

    private val vectors: JSONObject by lazy {
        val file = File("src/test/resources/vectors.json")
        check(file.exists()) { "vectors.json is missing; run `npm run vectors` at the repository root" }
        JSONObject(file.readText())
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun unhex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `handle hashes match the reference implementation`() {
        val vector = vectors.getJSONObject("username")
        assertEquals(vector.getInt("nicknameMinLength"), Handles.NICKNAME_MIN_LENGTH)
        assertEquals(vector.getInt("nicknameMaxLength"), Handles.NICKNAME_MAX_LENGTH)
        assertEquals(vector.getInt("hashBytes"), Handles.USERNAME_HASH_BYTES)
        assertEquals(vector.getInt("proofBytes"), Handles.USERNAME_PROOF_BYTES)

        val cases = vector.getJSONArray("cases")
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val username = case.getString("username")
            assertEquals(case.getString("hashHex"), hex(Handles.hash(username)), "hash for $username")
        }
    }

    @Test
    fun `a proof made by the reference implementation verifies here`() {
        val proof = vectors.getJSONObject("username").getJSONObject("proof")
        val hash = unhex(proof.getString("hashHex"))
        val bytes = unhex(proof.getString("proofHex"))

        assertEquals(hex(Handles.hash(proof.getString("username"))), hex(hash))
        assertTrue(Handles.verifyProof(bytes, hash), "a proof from the other implementation must verify")

        // And it must not verify against somebody else's name, or the proof
        // would establish nothing about which handle was known.
        val other = Handles.hash(Handles.candidates("someoneelse").first())
        assertTrue(!Handles.verifyProof(bytes, other), "a proof must not verify against another handle")
    }

    @Test
    fun `handles the reference implementation refuses are refused here`() {
        val invalid = vectors.getJSONObject("username").getJSONArray("invalid")
        for (index in 0 until invalid.length()) {
            val value = invalid.getString(index)
            assertTrue(!Handles.isValidUsername(value), "$value should not be a valid handle")
        }
    }

    @Test
    fun `an invite made by the reference implementation opens here`() {
        // The whole of an introduction. Handles carry digits nobody can guess
        // and there is no directory to browse, so being told a name is the only
        // way to be found — and an invite is that, made transferable. If the two
        // sides framed it differently, tapping one would simply do nothing, and
        // nobody reports that as a bug.
        val vector = vectors.getJSONObject("usernameLink")
        assertEquals(vector.getString("prefix"), Handles.LINK_PREFIX)
        assertEquals(vector.getInt("packedBytes"), Handles.LINK_BYTES)

        val link = vector.getString("link")
        assertEquals(vector.getString("username"), Handles.usernameFromLink(link))
    }

    @Test
    fun `an invite made here opens here`() {
        val username = Handles.candidates("dilnoza").first()
        assertEquals(username, Handles.usernameFromLink(Handles.createLink(username)))
    }

    @Test
    fun `a damaged or foreign invite resolves to nothing rather than throwing`() {
        // Every one of these arrives the same way — somebody pasting into a
        // field — so none of them is exceptional enough to be an exception.
        val good = Handles.createLink(Handles.candidates("dilnoza").first())
        assertNull(Handles.usernameFromLink(good.dropLast(4)), "a truncated paste")
        assertNull(Handles.usernameFromLink(good.dropLast(2) + "AA"), "a tampered ciphertext")
        assertNull(Handles.usernameFromLink(good.removePrefix(Handles.LINK_PREFIX)), "no prefix")
        assertNull(Handles.usernameFromLink("mg1:not-base64!!"), "not base64url")
        assertNull(Handles.usernameFromLink("https://example.invalid/u/abc"), "something else entirely")
        assertNull(Handles.usernameFromLink(""), "nothing at all")
    }
}
