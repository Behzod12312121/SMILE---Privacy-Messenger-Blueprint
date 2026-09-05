package uz.millygram.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The two implementations must run the same libsignal.
 *
 * They did not, once. Maven Central lags Signal's own artifact host badly —
 * 0.86.5 against 0.101.2 — so the obvious dependency coordinate silently put
 * Android fifteen minor versions behind the gateway. Nothing was visibly
 * broken; the cost was that sealed-sender certificate validation and HPKE
 * interop became questions answerable only on a device, against a live server.
 *
 * Aligning the versions removed those questions. This test is what stops them
 * coming back: `npm run vectors` records the gateway's version, Gradle injects
 * Android's, and a mismatch fails the build rather than waiting to be noticed.
 */
class LibsignalVersionTest {

    @Test
    fun `android and the gateway run the same libsignal`() {
        val gatewayVersion = checkNotNull(
            javaClass.classLoader.getResourceAsStream("gateway-libsignal-version.txt"),
        ) {
            "gateway-libsignal-version.txt is missing; run `npm run vectors` at the repository root"
        }.bufferedReader().use { it.readText() }.trim()

        val androidVersion = checkNotNull(System.getProperty("millygram.libsignalVersion")) {
            "the build must inject millygram.libsignalVersion; see client/build.gradle.kts"
        }

        assertTrue(gatewayVersion.isNotEmpty(), "the recorded gateway version is empty")

        assertEquals(
            gatewayVersion,
            androidVersion,
            "libsignal has drifted: the gateway runs $gatewayVersion and Android runs $androidVersion. " +
                "Align them — do not paper over it with a compatibility note.",
        )
    }
}
