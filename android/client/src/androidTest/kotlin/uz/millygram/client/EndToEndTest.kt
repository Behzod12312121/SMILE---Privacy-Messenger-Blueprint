package uz.millygram.client

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The end-to-end test.
 *
 * Everything else in this repository is a unit test, a conformance vector or a
 * Node-to-Node demo. None of them prove the thing the product actually has to
 * do: a message leaving an Android device, passing through the real gateway,
 * and arriving at another Android device, decrypted.
 *
 * It runs against a gateway on the developer's machine, reached at the
 * emulator's 10.0.2.2 loopback alias. That is deliberate — a mocked transport
 * would test this file's own assumptions rather than the server's behaviour,
 * and the two libsignal questions this settles (sealed-sender certificates and
 * HPKE across the JNI boundary) can only be answered against real native code.
 *
 * Start the gateway first:
 *     MG_HOST=127.0.0.1 MG_PORT=8443 npm run relay
 */
@RunWith(AndroidJUnit4::class)
class EndToEndTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val gatewayUrl: String =
        InstrumentationRegistry.getArguments().getString("gatewayUrl") ?: "http://10.0.2.2:8443"

    private val databases = mutableListOf<String>()
    private val clients = mutableListOf<MillygramClient>()

    /** A fresh vault per client per run, so a rerun never reuses an account. */
    private fun freshDatabase(label: String): String =
        "e2e-$label-${UUID.randomUUID().toString().take(8)}.db".also { databases += it }

    private fun freshUsername(label: String): String =
        (label + UUID.randomUUID().toString().replace("-", "")).take(24).lowercase()

    private fun register(label: String): MillygramClient {
        val client = MillygramClient.register(
            MillygramRegisterOptions(
                username = freshUsername(label),
                base = MillygramOptions(
                    context = context,
                    databaseName = freshDatabase(label),
                    passphrase = "instrumented test passphrase for $label",
                    serverUrl = gatewayUrl,
                ),
            ),
        )
        clients += client
        return client
    }

    @Before
    fun checkGatewayIsReachable() {
        val reachable = runCatching {
            java.net.URL("$gatewayUrl/v1/trust-root").openConnection().apply {
                connectTimeout = 3000
                readTimeout = 3000
            }.getInputStream().use { it.readBytes().isNotEmpty() }
        }.getOrDefault(false)

        assertTrue(
            "no gateway at $gatewayUrl — start it with `npm run relay` on the host first",
            reachable,
        )
    }

    @After
    fun cleanUp() {
        clients.forEach { runCatching { it.close() } }
        databases.forEach { runCatching { context.deleteDatabase(it) } }
    }

    @Test
    fun aMessageTravelsFromOneDeviceToAnotherThroughTheRealGateway() {
        val alisher = register("alisher")
        val nodira = register("nodira")

        // Uzbek text with both modifier letters, so the round trip is proved
        // over the characters that actually get mangled by a bad encoding path
        // rather than over ASCII that would survive almost anything.
        val body = "Salom! Ertaga soat 10 da uchrashamizmi? — Gʻayrat, maʼlumot"

        alisher.send(nodira.username, body)

        val received = mutableListOf<MillygramClient.IncomingMessage>()
        nodira.catchUp { received += it }

        assertEquals("exactly one message should have arrived", 1, received.size)
        assertEquals("the body must survive the round trip byte for byte", body, received[0].body)
        assertEquals(
            "sealed sender must still resolve the real author",
            alisher.aci,
            received[0].senderAci,
        )
    }

    @Test
    fun bothSidesComputeTheSameSafetyNumber() {
        val alisher = register("safetya")
        val nodira = register("safetyb")

        // A safety number needs both identity keys, so a message has to have
        // travelled in each direction before either side can compute one.
        alisher.send(nodira.username, "birinchi xabar")
        nodira.catchUp { }
        nodira.send(alisher.aci, "javob")
        alisher.catchUp { }

        val fromAlisher = alisher.safetyNumber(nodira.aci)
        val fromNodira = nodira.safetyNumber(alisher.aci)

        assertEquals(
            "a relay that swapped a key could not make these agree",
            fromAlisher,
            fromNodira,
        )
        assertEquals("safety numbers are 60 digits", 60, fromAlisher.filter { it.isDigit() }.length)
    }

    @Test
    fun aBucketPeerReceivesTheEnvelopeAndCannotOpenIt() {
        val alisher = register("peera")
        val nodira = register("peerb")
        val eavesdropper = register("peerc")

        alisher.send(nodira.username, "faqat Nodira uchun")

        val overheard = mutableListOf<MillygramClient.IncomingMessage>()
        eavesdropper.catchUp { overheard += it }

        // The eavesdropper polls the same bucket and downloads whatever is in
        // it. Whether that included this envelope depends on bucket assignment,
        // but under no assignment may it ever open one.
        assertTrue(
            "a bucket peer must never decrypt someone else's message",
            overheard.none { it.body == "faqat Nodira uchun" },
        )
    }

    @Test
    fun anAccountSurvivesBeingClosedAndReopened() {
        val label = "reopen"
        val database = freshDatabase(label)
        val passphrase = "a passphrase that must round trip"
        val username = freshUsername(label)

        val options = MillygramOptions(
            context = context,
            databaseName = database,
            passphrase = passphrase,
            serverUrl = gatewayUrl,
        )

        val first = MillygramClient.register(MillygramRegisterOptions(username, options))
        val aci = first.aci
        first.close()

        val reopened = MillygramClient.open(options)
        clients += reopened

        assertEquals("the account identity must survive a restart", aci, reopened.aci)
        assertEquals(username, reopened.username)
        assertNotNull(reopened.bucketId)
    }
}
