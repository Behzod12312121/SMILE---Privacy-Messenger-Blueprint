package uz.millygram.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What the onboarding field will let someone type has to agree with what the
 * gateway will accept, or the field takes a name and the protocol refuses it a
 * moment later.
 *
 * The field takes a nickname only. The four digits after it are the gateway's
 * to choose, so nothing here can produce a whole handle and nothing here should
 * try to validate one.
 */
class NicknameTest {

    @Test
    fun `cyrillic is removed rather than carried to a later refusal`() {
        // Uzbek is written in both scripts and this one is a keyboard away.
        assertEquals("", Protocol.sanitizeNickname("дилноза"))
        assertEquals("dilnoza", Protocol.sanitizeNickname("dilnozaд"))
    }

    @Test
    fun `a latin name with one cyrillic lookalike loses the lookalike`() {
        // U+0430 renders exactly like a Latin a. Admitting both would let one
        // person be mistaken for another, which is why the pattern is ASCII.
        val lookalike = "dilnoz\u0430"
        assertTrue(!Protocol.isValidNickname(lookalike))
        assertEquals("dilnoz", Protocol.sanitizeNickname(lookalike))
    }

    @Test
    fun `anything it produces is either empty, too short, or valid`() {
        val inputs = listOf(
            "Dilnoza_AZ", "  spaced  out ", "emoji🙂name", "ALLCAPS", "dots.and-dashes",
            "a".repeat(100), "١٢٣", "日本語", "_", "ab", "abc",
        )
        for (input in inputs) {
            val cleaned = Protocol.sanitizeNickname(input)
            assertTrue(
                cleaned.length < 3 || Protocol.isValidNickname(cleaned),
                "sanitising $input produced $cleaned, which the protocol would refuse",
            )
            assertTrue(cleaned.length <= Protocol.NICKNAME_MAX_LENGTH)
        }
    }



/** The gateway accepts one shape of number; the client must agree on it. */
}

class PhoneNumberTest {
    @Test
    fun `international form only`() {
        assertTrue(Protocol.isValidPhoneNumber("+998901234567"))
        assertTrue(Protocol.isValidPhoneNumber("+441234567890"))
        // No country code, a leading zero, too short, too long, not digits.
        assertTrue(!Protocol.isValidPhoneNumber("998901234567"))
        assertTrue(!Protocol.isValidPhoneNumber("+0123456789"))
        assertTrue(!Protocol.isValidPhoneNumber("+1234567"))
        assertTrue(!Protocol.isValidPhoneNumber("+9989012345678901"))
        assertTrue(!Protocol.isValidPhoneNumber("+998 90 123 45 67"))
    }
}
