package uz.millygram.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What the onboarding field will let someone type has to agree with what the
 * gateway will accept, or the field takes a name and the protocol refuses it a
 * moment later.
 */
class UsernameTest {

    @Test
    fun `cyrillic is removed rather than carried to a later refusal`() {
        // Uzbek is written in both scripts and this one is a keyboard away.
        assertEquals("", Protocol.sanitizeUsername("дилноза"))
        assertEquals("dilnoza", Protocol.sanitizeUsername("dilnozaд"))
    }

    @Test
    fun `a latin name with one cyrillic lookalike loses the lookalike`() {
        // U+0430 renders exactly like a Latin a. Admitting both would let one
        // person be mistaken for another, which is why the pattern is ASCII.
        val lookalike = "dilnoz\u0430"
        assertTrue(!Protocol.isValidUsername(lookalike))
        assertEquals("dilnoz", Protocol.sanitizeUsername(lookalike))
    }

    @Test
    fun `anything it produces is either empty, too short, or valid`() {
        val inputs = listOf(
            "Dilnoza_AZ", "  spaced  out ", "emoji🙂name", "ALLCAPS", "dots.and-dashes",
            "a".repeat(100), "١٢٣", "日本語", "_", "ab", "abc",
        )
        for (input in inputs) {
            val cleaned = Protocol.sanitizeUsername(input)
            assertTrue(
                cleaned.length < 3 || Protocol.isValidUsername(cleaned),
                "sanitising $input produced $cleaned, which the protocol would refuse",
            )
            assertTrue(cleaned.length <= Protocol.USERNAME_MAX_LENGTH)
        }
    }
}
