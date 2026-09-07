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
import uz.millygram.protocol.Protocol

/**
 * The end-to-end test.
 *
 * Everything else in this repository is a unit test, a conformance vector or a
 * Node-to-Node demo. None of them prove the thing the product actually has to
 * do: a message leaving an Android device, passing through the real gateway,
 * and arriving at another Android device, decrypted.
 *
 * It runs against a gateway on the developer's machine, reached at localhost
 * through an adb reverse tunnel. That works the same on an emulator and on a
 * handset, unlike the 10.0.2.2 alias, which only exists on an emulator and
 * failed every run on real hardware. That is deliberate — a mocked transport
 * would test this file's own assumptions rather than the server's behaviour,
 * and the two libsignal questions this settles (sealed-sender certificates and
 * HPKE across the JNI boundary) can only be answered against real native code.
 *
 * Start the gateway first:
 *     MG_HOST=127.0.0.1 MG_PORT=8443 npm run relay
 *     adb reverse tcp:8443 tcp:8443
 */
@RunWith(AndroidJUnit4::class)
class EndToEndTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val gatewayUrl: String =
        InstrumentationRegistry.getArguments().getString("gatewayUrl") ?: "http://localhost:8443"

    private val databases = mutableListOf<String>()
    private val clients = mutableListOf<MillygramClient>()

    /** A fresh vault per client per run, so a rerun never reuses an account. */
    private fun freshDatabase(label: String): String =
        "e2e-$label-${UUID.randomUUID().toString().take(8)}.db".also { databases += it }

    private fun freshUsername(label: String): String =
        (label + UUID.randomUUID().toString().replace("-", "")).take(24).lowercase()

    private val vaults = mutableMapOf<String, Pair<String, String>>()

    private fun register(label: String, relayUrl: String? = null): MillygramClient {
        val database = freshDatabase(label)
        val passphrase = "instrumented test passphrase for $label"
        val client = MillygramClient.register(
            MillygramRegisterOptions(
                username = freshUsername(label),
                base = MillygramOptions(
                    context = context,
                    databaseName = database,
                    passphrase = passphrase,
                    serverUrl = gatewayUrl,
                    obliviousRelayUrl = relayUrl,
                ),
            ),
        )
        clients += client
        vaults[client.aci] = database to passphrase
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
            "no gateway at $gatewayUrl — run `npm run relay` on the host and " +
                "`adb reverse tcp:8443 tcp:8443` for this device first",
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
    fun aSubstitutedIdentityKeyIsReportedRatherThanSilentlyDropped() {
        val alisher = register("swapa")
        val nodira = register("swapb")

        // First exchange pins Alisher's identity in Nodira's vault.
        alisher.send(nodira.username, "birinchi")
        val firstPass = mutableListOf<MillygramClient.IncomingMessage>()
        nodira.catchUp { firstPass += it }
        assertEquals("the first message must arrive normally", 1, firstPass.size)

        // Overwrite the pin with somebody else's key. This is what Nodira's
        // device would see if the relay had answered a prekey request with an
        // identity of its own choosing: the ACI is unchanged, the key is not.
        val (database, passphrase) = vaults.getValue(nodira.aci)
        val impostor = org.signal.libsignal.protocol.IdentityKeyPair.generate()
        LocalStore.open(context, database, passphrase).use { vault ->
            vault.writeIdentity(
                "${alisher.aci}.${uz.millygram.protocol.Protocol.DEVICE_ID_PRIMARY}",
                impostor.publicKey.serialize(),
            )
        }

        val reported = mutableListOf<String>()
        nodira.onIdentityMismatch = { reported += it }

        alisher.send(nodira.aci, "ikkinchi")
        val secondPass = mutableListOf<MillygramClient.IncomingMessage>()
        nodira.catchUp { secondPass += it }

        // The message must not be delivered — the key did not check out.
        assertTrue("a message under an unpinned key must not be delivered", secondPass.isEmpty())
        // And it must not be swallowed either. Silence here is exactly what an
        // envelope for another bucket member produces, so a relay substituting
        // keys would be indistinguishable from ordinary traffic.
        assertEquals("the mismatch must be reported exactly once", 1, reported.size)
        assertEquals("the report must name the sender", alisher.aci, reported[0])
    }

    @Test
    fun aConfiguredRelayIsNeverBypassed() {
        // Port 1 has nothing on it. The gateway is reachable throughout, so a
        // client that quietly fell back to submitting directly would succeed
        // here — and the sender's address would reach the gateway despite the
        // user having asked for a relay. Downgrading a privacy control without
        // saying so is worse than failing, so this must throw.
        val sender = register("relaya", relayUrl = "http://127.0.0.1:1")
        val recipient = register("relayb")

        var threw = false
        try {
            sender.send(recipient.username, "rele orqali")
        } catch (_: Throwable) {
            threw = true
        }

        assertTrue("a send through an unreachable relay must fail", threw)

        val received = mutableListOf<MillygramClient.IncomingMessage>()
        recipient.catchUp { received += it }
        assertTrue("nothing may reach the gateway by the direct path", received.isEmpty())
    }

    @Test
    fun twoSendsAtOnceAreBothDelivered() {
        val sender = register("racea")
        val receiver = register("raceb")

        // Establish the session first, so this exercises concurrent use of an
        // existing ratchet rather than concurrent session setup.
        sender.send(receiver.username, "warm up")
        receiver.catchUp { }

        // The Double Ratchet is read-modify-write. Unserialised, both threads
        // encrypt from the same session state and the later write discards the
        // earlier ratchet advance: both calls return normally, the relay takes
        // both envelopes, and the recipient can only follow one chain — so one
        // message is lost with nothing reporting a failure.
        val start = java.util.concurrent.CountDownLatch(1)
        val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
        val threads = listOf("one", "two").map { body ->
            Thread {
                start.await()
                runCatching { sender.send(receiver.aci, body) }
                    .onFailure { failures += it }
            }.also { it.start() }
        }
        start.countDown()
        threads.forEach { it.join(60_000) }

        assertTrue("neither send should fail: $failures", failures.isEmpty())

        val received = mutableListOf<String>()
        receiver.catchUp { received += it.body }

        assertEquals(
            "a concurrent send must not be silently dropped",
            listOf("one", "two"),
            received.sorted(),
        )
    }

    @Test
    fun aMessageAtTheDocumentedLimitFitsAndOneOverItIsRefused() {
        val sender = register("limita")
        val recipient = register("limitb")

        // The limit is a byte count, and the whole payload — JSON wrapper,
        // sealed-sender overhead, padding to a fixed envelope — has to fit
        // around it. A limit the protocol advertises but cannot actually carry
        // would fail at the worst possible moment: on the longest message
        // somebody had just finished writing.
        val atLimit = "a".repeat(Protocol.MAX_PLAINTEXT_BYTES)
        assertEquals(Protocol.MAX_PLAINTEXT_BYTES, atLimit.toByteArray(Charsets.UTF_8).size)
        sender.send(recipient.username, atLimit)

        val received = mutableListOf<String>()
        recipient.catchUp { received += it.body }
        assertEquals("a message at the limit must be deliverable", listOf(atLimit), received)

        // And one byte more is refused by the client rather than by the relay,
        // so nothing is spent solving work for an envelope that cannot be sent.
        var refused = false
        try {
            sender.send(recipient.aci, "a".repeat(Protocol.MAX_PLAINTEXT_BYTES + 1))
        } catch (_: IllegalArgumentException) {
            refused = true
        }
        assertTrue("a body over the limit must be refused", refused)
    }

    @Test
    fun rotatingPreKeysKeepsTheReplacedOneUsable() {
        val owner = register("rotowner")
        val early = register("rotearly")
        val late = register("rotlate")

        // Someone fetches a bundle and writes, but the message has not been
        // collected when the rotation happens.
        early.send(owner.username, "eski kalit bilan yuborildi")

        owner.rotatePreKeys(System.currentTimeMillis() + Protocol.PREKEY_ROTATION_MS + 1)

        // The in-flight session names the key that was just replaced. Losing it
        // would be silent: an envelope that will not open is exactly what every
        // other member of the bucket sees.
        val first = mutableListOf<String>()
        owner.catchUp { first += it.body }
        assertEquals(
            "a session opened before rotation must still be readable",
            listOf("eski kalit bilan yuborildi"),
            first,
        )

        // And the newly published pair works for someone arriving after it.
        late.send(owner.username, "yangi kalit bilan yuborildi")
        val second = mutableListOf<String>()
        owner.catchUp { second += it.body }
        assertEquals(listOf("yangi kalit bilan yuborildi"), second)
    }

    @Test
    fun aMessageCarriesTheSendersHandleForTheRecipientToCheck() {
        val sender = register("handlea")
        val recipient = register("handleb")

        sender.send(recipient.username, "salom")

        val received = mutableListOf<MillygramClient.IncomingMessage>()
        recipient.catchUp { received += it }

        assertEquals(1, received.size)
        assertEquals(
            "a first message must arrive with something to call the sender",
            sender.username,
            received[0].senderUsername,
        )

        // And the claim has to be checkable, because it is only a claim: the
        // sealed sender proves which account sent this, not what it is named.
        // The directory runs handle to identifier, which is the safe direction
        // — the reverse would let anyone enumerate who owns an account.
        assertEquals(
            sender.aci,
            recipient.resolveUsername(received[0].senderUsername!!).aci,
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
