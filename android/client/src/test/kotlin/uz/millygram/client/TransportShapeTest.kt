package uz.millygram.client

import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.json.JSONObject
import uz.millygram.protocol.Protocol

/**
 * The requests this client puts on the wire must match what the Node gateway
 * parses. These tests assert the exact shapes — method, path, headers, JSON
 * field names — against a mock server, so a rename on either side fails here
 * rather than in the field.
 *
 * Nothing here touches libsignal natives or Android, so it runs on the JVM.
 */
class TransportShapeTest {

    private lateinit var server: MockWebServer
    private lateinit var transport: Transport

    /** A deterministic stand-in for the identity key, so signatures are reproducible. */
    private class FakeCredentials(
        override val aci: String = "4aecbadd-bec0-4e2f-8f5d-71e0ace76688",
        override val deviceId: Int = 1,
    ) : Credentials {
        var lastSigned: ByteArray? = null
        override fun sign(payload: ByteArray): ByteArray {
            lastSigned = payload
            return ByteArray(64) { 7 }
        }
    }

    private val credentials = FakeCredentials()

    @BeforeTest
    fun start() {
        server = MockWebServer()
        server.start()
        transport = Transport(baseUrl = server.url("/").toString().trimEnd('/'), credentials = credentials)
    }

    @AfterTest
    fun stop() {
        server.shutdown()
    }

    private fun take(): RecordedRequest = server.takeRequest(5, TimeUnit.SECONDS)!!

    private fun enqueueJson(status: Int, body: String) {
        server.enqueue(MockResponse().setResponseCode(status).setBody(body))
    }

    /** Both halves of the challenge-response handshake, so `auth = true` calls can proceed. */
    private fun enqueueAuth() {
        enqueueJson(200, JSONObject().apply {
            put("nonce", Protocol.b64(ByteArray(32) { 3 }))
            put("expiresAt", System.currentTimeMillis() + 60_000)
        }.toString())
        enqueueJson(200, JSONObject().apply {
            put("token", "a-test-token")
            put("expiresAt", System.currentTimeMillis() + 900_000)
        }.toString())
    }

    @Test
    fun `registration posts the field names the gateway parses`() {
        enqueueJson(201, JSONObject().apply {
            put("aci", "4aecbadd-bec0-4e2f-8f5d-71e0ace76688")
            put("bucketId", 0)
            put("trustRoot", Protocol.b64(ByteArray(33) { 1 }))
            put("powDifficulty", 12)
        }.toString())

        val response = transport.register(JSONObject().apply {
            put("usernameHash", Protocol.b64(ByteArray(32) { 7 }))
            put("deviceId", 1)
        })

        val request = take()
        assertEquals("POST", request.method)
        assertEquals("/v1/accounts", request.path)
        assertEquals("application/json", request.getHeader("Content-Type")?.substringBefore(';'))

        assertEquals("4aecbadd-bec0-4e2f-8f5d-71e0ace76688", response.aci)
        assertEquals(0L, response.bucketId)
        assertEquals(12, response.powDifficulty)
    }

    @Test
    fun `auth signs the canonical challenge payload and reuses the token`() {
        enqueueAuth()
        enqueueJson(200, """{"oneTimePreKeys":42}""")

        assertEquals(42, transport.remainingOneTimePreKeys())

        val challenge = take()
        assertEquals("GET", challenge.method)
        assertTrue(challenge.path!!.startsWith("/v1/accounts/challenge?aci="))

        val auth = take()
        assertEquals("POST", auth.method)
        assertEquals("/v1/accounts/auth", auth.path)

        // The signature must cover exactly the canonical payload, not the raw nonce.
        val expected = Protocol.authSigningPayload(credentials.aci, 1, ByteArray(32) { 3 })
        assertTrue(expected.contentEquals(credentials.lastSigned), "auth must sign the canonical payload")

        val counted = take()
        assertEquals("Bearer a-test-token", counted.getHeader("Authorization"))

        // A second authenticated call must reuse the cached token, not re-handshake.
        enqueueJson(200, """{"oneTimePreKeys":41}""")
        assertEquals(41, transport.remainingOneTimePreKeys())
        assertEquals("Bearer a-test-token", take().getHeader("Authorization"))
    }

    @Test
    fun `direct submit carries bucket, content and nonce and no identity`() {
        enqueueJson(202, "")

        val content = ByteArray(Protocol.PADDED_ENVELOPE_BYTES) { (it % 7).toByte() }
        transport.submit(bucketId = 3, content = content, difficulty = 8)

        val request = take()
        assertEquals("PUT", request.method)
        assertEquals("/v1/messages", request.path)

        // The whole point of this endpoint: it must carry nothing that names a sender.
        assertNull(request.getHeader("Authorization"), "a submission must not be authenticated")
        assertNull(request.getHeader("Cookie"))

        val body = JSONObject(request.body.readUtf8())
        assertEquals(3L, body.getLong("bucketId"))
        assertTrue(body.has("nonce"))
        assertTrue(
            Protocol.verifyProofOfWork(3, content, body.getLong("nonce"), 8),
            "the submitted nonce must satisfy the difficulty it claims",
        )
        assertTrue(content.contentEquals(Protocol.unb64(body.getString("content"))))
    }

    @Test
    fun `since parses the envelope list and passes the cursor`() {
        enqueueAuth()
        enqueueJson(200, JSONObject().apply {
            put("envelopes", org.json.JSONArray().apply {
                put(JSONObject().apply {
                    put("seq", 9)
                    put("content", Protocol.b64(ByteArray(16) { 4 }))
                    put("arrivedAt", 1788435744566L)
                })
            })
        }.toString())

        val envelopes = transport.since(7)
        take(); take()

        val request = take()
        assertEquals("/v1/messages?since=7", request.path)
        assertEquals(1, envelopes.size)
        assertEquals(9L, envelopes[0].seq)
        assertEquals(1788435744566L, envelopes[0].arrivedAt)
    }

    @Test
    fun `a poisoned envelope in a catch-up batch is skipped, not thrown`() {
        enqueueAuth()
        // The gateway decides what goes in this list, and a hostile one is
        // inside the threat model. Three of these four entries are unusable:
        // content that is not base64 at all, content of an impossible length,
        // and an entry missing the sequence number entirely.
        enqueueJson(
            200,
            """
            {"envelopes":[
              {"seq":1,"content":"!!!!","arrivedAt":1},
              {"seq":2,"content":"AAAAA","arrivedAt":2},
              {"content":"${Protocol.b64(ByteArray(8) { 1 })}","arrivedAt":3},
              {"seq":4,"content":"${Protocol.b64(ByteArray(8) { 9 })}","arrivedAt":4}
            ]}
            """.trimIndent(),
        )

        // Throwing here would fail the whole catch-up and leave the cursor
        // unmoved, so every later attempt would fetch the same poisoned batch
        // and nothing would ever be delivered again — silently, because the
        // caller treats a failed catch-up as nothing to do.
        val envelopes = transport.since(0)

        assertEquals(1, envelopes.size, "only the usable envelope should survive")
        assertEquals(4L, envelopes[0].seq)
    }

    @Test
    fun `a catch-up response with no envelope list is empty, not fatal`() {
        enqueueAuth()
        enqueueJson(200, """{"envelopes":null}""")
        assertEquals(0, transport.since(0).size)
    }

    @Test
    fun `an error response becomes a TransportError carrying the server code`() {
        // Not a submission: any other refusal must still surface unchanged.
        enqueueJson(409, """{"error":"duplicate_submission"}""")

        val failure = assertFailsWith<TransportError> {
            transport.submit(1, ByteArray(Protocol.PADDED_ENVELOPE_BYTES), 4)
        }
        assertEquals(409, failure.status)
        assertEquals("duplicate_submission", failure.code)
    }

    @Test
    fun `a bucket that asks a higher price is paid rather than reported`() {
        // A bucket whose shared inbound budget is draining charges extra work
        // and names the figure. There is no sender identity to throttle -- a
        // submission is anonymous by construction -- so the price is the only
        // lever the gateway has, and an honest sender that treated the quote as
        // a refusal would leave the flooder holding sixteen accounts down.
        enqueueJson(400, """{"error":"insufficient_proof_of_work","difficulty":12}""")
        enqueueJson(202, "")

        transport.submit(1, ByteArray(Protocol.PADDED_ENVELOPE_BYTES), 4)

        take()
        val paid = take()
        val nonce = JSONObject(paid.body.readUtf8()).getLong("nonce")
        assertTrue(
            Protocol.verifyProofOfWork(1, ByteArray(Protocol.PADDED_ENVELOPE_BYTES), nonce, 12),
            "the second attempt must carry work at the difficulty the gateway asked for",
        )
    }

    @Test
    fun `a price that keeps rising is reported rather than paid forever`() {
        // Two raises inside one send means the bucket is draining faster than a
        // handset can answer. Paying without limit is how a sender becomes the
        // flooder's battery, so the second quote is surfaced, not solved.
        enqueueJson(400, """{"error":"insufficient_proof_of_work","difficulty":12}""")
        enqueueJson(400, """{"error":"insufficient_proof_of_work","difficulty":14}""")

        val failure = assertFailsWith<TransportError> {
            transport.submit(1, ByteArray(Protocol.PADDED_ENVELOPE_BYTES), 4)
        }
        assertEquals("insufficient_proof_of_work", failure.code)
        assertEquals(14, failure.requiredDifficulty)
    }

    @Test
    fun `directory lookup returns the peer bucket the send path needs`() {
        enqueueAuth()
        enqueueJson(200, """{"aci":"90ce12e4-2da3-4998-a924-1b948ae1ff42","deviceId":1,"bucketId":5}""")

        val entry = transport.lookupUsername("gayrat.42")
        take(); take()

        // The path carries the hash and nothing else. This is the assertion
        // that the name never leaves the device: if a future change put the
        // handle back into the URL, the gateway would be learning who was being
        // looked up again and this is what would notice.
        val path = take().path.orEmpty()
        assertEquals("/v1/directory/" + Protocol.b64(Handles.hash("gayrat.42")), path)
        assertTrue(!path.contains("gayrat"), "the handle must not appear in the request")
        assertEquals("90ce12e4-2da3-4998-a924-1b948ae1ff42", entry.aci)
        assertEquals(5L, entry.bucketId)
    }
}
