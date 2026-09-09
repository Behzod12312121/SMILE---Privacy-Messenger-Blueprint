package uz.millygram.app.data

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import uz.millygram.client.TransportError

/**
 * What the user is told when the gateway refuses something.
 *
 * The failure that prompted this: registering against a gateway running older
 * code answered `invalid_request (HTTP 400)`, and the screen said "could not
 * connect to the server". An hour went into checking DNS, TLS, the Funnel and
 * the phone's network — all of which were fine — because the one thing the
 * message ruled out was the one thing that had happened.
 *
 * TransportError extends IOException, so a refusal the gateway spelled out in
 * words falls into the branch meant for a socket that never opened. Known codes
 * are matched by string before that branch and survive; anything not on the
 * list does not.
 */
class GatewayErrorsTest {

    private val cannotConnect = "Serverga ulanib boʻlmadi"

    @Test
    fun `a refusal the gateway named is not reported as a connection failure`() {
        // The exact error that cost the hour.
        assertEquals(
            "Server soʻrovni rad etdi (invalid_request)",
            describeGatewayFailure(TransportError(400, "invalid_request")),
            "an HTTP 400 the gateway explained must not be reported as an unreachable server",
        )
    }

    @Test
    fun `a genuine transport failure still reports as one`() {
        assertEquals(cannotConnect, describeGatewayFailure(IOException("Failed to connect to /10.0.0.1:8443")))
        assertEquals(cannotConnect, describeGatewayFailure(IOException("Unable to resolve host")))
        assertEquals(cannotConnect, describeGatewayFailure(IOException("timeout")))
    }

    @Test
    fun `the codes that were already handled keep their wording`() {
        assertEquals("Bu nom band", describeGatewayFailure(TransportError(409, "username_taken")))
        assertEquals("Bunday foydalanuvchi topilmadi", describeGatewayFailure(TransportError(404, "not_found")))
        assertEquals("Juda koʻp urinish. Biroz kuting", describeGatewayFailure(TransportError(429, "slow_down")))
        assertEquals(
            "Qurilma soati notoʻgʻri. Sana va vaqtni tekshiring",
            describeGatewayFailure(TransportError(400, "clock_skew")),
        )
        assertEquals(
            "Server band. Biroz kutib, qayta urinib koʻring",
            describeGatewayFailure(TransportError(400, "work_required")),
        )
    }
}
