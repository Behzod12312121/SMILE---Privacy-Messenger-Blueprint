package uz.millygram.client

import java.io.Closeable
import java.io.IOException
import java.time.Duration
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import uz.millygram.protocol.Protocol

/**
 * The relay-facing transport. HTTP calls are synchronous by design — every
 * call has bounded work and the caller is a background service, not the UI
 * thread. Structured concurrency lives in the layer above.
 *
 * There is no logger in this class deliberately. A log statement here could
 * write an auth token or a URL to disk, and both are exactly the metadata this
 * project exists not to keep.
 */
class TransportError(
    val status: Int,
    val code: String,
    /**
     * Set when the gateway answered `work_required`: the difficulty it will
     * accept. Lets the server raise the price under load without every client
     * needing a new build.
     */
    val requiredDifficulty: Int? = null,
) : IOException("$code (HTTP $status)")

interface Credentials {
    val aci: String
    val deviceId: Int
    /** Signs `payload` with the local identity private key. */
    fun sign(payload: ByteArray): ByteArray
}

class Transport(
    private val baseUrl: String,
    private var credentials: Credentials? = null,
    /** When set, submissions go through this relay instead of straight to the gateway. */
    private val obliviousRelayUrl: String? = null,
    private val client: OkHttpClient = OkHttpClient.Builder().build(),
) {

    /** Refresh a bearer token a little before it expires so a request never races it. */
    private val tokenRefreshMarginMs = 30_000L

    private data class Token(val value: String, val expiresAt: Long)

    private var token: Token? = null

    /**
     * The gateway's HPKE public key, fetched once and kept. Submissions are
     * sealed to it so the relay forwards a body it cannot read.
     */
    private var obliviousKey: ByteArray? = null

    fun setCredentials(newCredentials: Credentials) {
        credentials = newCredentials
        token = null
    }

    /* ---- account ---- */

    data class RegisterResponse(val aci: String, val bucketId: Long, val trustRoot: String, val powDifficulty: Int)

    fun register(request: JSONObject): RegisterResponse {
        val body = json(post("/v1/accounts", request))
        return RegisterResponse(
            aci = body.getString("aci"),
            bucketId = body.getLong("bucketId"),
            trustRoot = body.getString("trustRoot"),
            powDifficulty = body.getInt("powDifficulty"),
        )
    }

    fun accessToken(): String {
        token?.takeIf { it.expiresAt - tokenRefreshMarginMs > System.currentTimeMillis() }?.let { return it.value }

        val creds = credentials ?: error("transport has no credentials")

        val challenge = json(get("/v1/accounts/challenge?aci=${urlEncode(creds.aci)}"))
        val nonce = Protocol.unb64(challenge.getString("nonce"))
        val signature = creds.sign(Protocol.authSigningPayload(creds.aci, creds.deviceId.toLong(), nonce))

        val response = json(post("/v1/accounts/auth", JSONObject().apply {
            put("aci", creds.aci)
            put("deviceId", creds.deviceId)
            put("nonce", challenge.getString("nonce"))
            put("signature", Protocol.b64(signature))
        }))

        val newToken = Token(response.getString("token"), response.getLong("expiresAt"))
        token = newToken
        return newToken.value
    }

    /* ---- directory and keys ---- */

    data class DirectoryEntry(val aci: String, val deviceId: Int, val bucketId: Long)

    fun lookupUsername(username: String): DirectoryEntry {
        val body = json(get("/v1/directory/${urlEncode(username)}", auth = true))
        return DirectoryEntry(
            aci = body.getString("aci"),
            deviceId = body.getInt("deviceId"),
            bucketId = body.getLong("bucketId"),
        )
    }

    /** The prekey bundle payload for a peer, returned as-is for the caller to consume. */
    fun fetchPreKeyBundle(aci: String): JSONObject = json(get("/v1/keys/${urlEncode(aci)}", auth = true))

    fun replenishKeys(body: JSONObject) {
        json(put("/v1/keys", body, auth = true))
    }

    fun remainingOneTimePreKeys(): Int = json(get("/v1/keys/count", auth = true)).getInt("oneTimePreKeys")

    data class DeliveryCertificate(val certificate: String, val expiresAt: Long)

    fun fetchDeliveryCertificate(): DeliveryCertificate {
        val body = json(get("/v1/certificate/delivery", auth = true))
        return DeliveryCertificate(body.getString("certificate"), body.getLong("expiresAt"))
    }

    /**
     * Fetched from the gateway directly rather than through the relay: it is a
     * public key, the request carries no authentication, and asking the relay
     * for it would tell the relay which gateway this device talks to.
     */
    fun fetchObliviousPublicKey(): ByteArray {
        obliviousKey?.let { return it }
        return Protocol.unb64(json(get("/v1/oblivious-key")).getString("publicKey"))
            .also { obliviousKey = it }
    }

    /* ---- messages ---- */

    /**
     * Solves the proof of work and submits the envelope. When configured with
     * an oblivious relay, the whole request is sealed to the gateway's key
     * and forwarded through it, so the gateway never sees this device's
     * address. Without the relay it goes straight to the gateway, still
     * anonymous in every other respect.
     */
    fun submit(bucketId: Long, content: ByteArray, difficulty: Int) {
        val nonce = Protocol.solveProofOfWork(bucketId, content, difficulty)

        val relayUrl = obliviousRelayUrl
        if (relayUrl == null) {
            val body = JSONObject().apply {
                put("bucketId", bucketId)
                put("content", Protocol.b64(content))
                put("nonce", nonce)
            }
            json(put("/v1/messages", body))
            return
        }

        val encoded = Protocol.encodeObliviousRequest(bucketId, nonce, content)
        val sealed = sealForGateway(fetchObliviousPublicKey(), encoded)
        val response = client
            .newCall(
                Request.Builder()
                    .url(relayUrl.toHttpUrl())
                    .post(sealed.toRequestBody("application/octet-stream".toMediaType()))
                    .build(),
            )
            .execute()
        response.use { checkStatus(it) }
    }

    data class Envelope(val seq: Long, val content: ByteArray, val arrivedAt: Long)

    fun since(cursor: Long): List<Envelope> {
        val body = json(get("/v1/messages?since=$cursor", auth = true))
        val array = body.optJSONArray("envelopes") ?: return emptyList()

        // Each entry is parsed on its own and a bad one is skipped, exactly as
        // the socket path already does. The gateway chooses what goes in this
        // list, and a hostile one is inside the threat model: a single envelope
        // with content that is not base64 would otherwise throw out of here,
        // fail the whole catch-up, and leave the cursor where it was — so every
        // later attempt fetches the same poisoned batch. The caller treats that
        // failure as nothing to do, so the app would sit there saying it is
        // online and never receive another message.
        return (0 until array.length()).mapNotNull { index ->
            runCatching {
                val entry = array.getJSONObject(index)
                Envelope(
                    seq = entry.getLong("seq"),
                    content = Protocol.unb64(entry.getString("content")),
                    arrivedAt = entry.getLong("arrivedAt"),
                )
            }.getOrNull()
        }
    }

    /* ---- internals ---- */

    /**
     * Sealed at the transport boundary rather than by the caller: the sealing
     * key is public, but its use is a protocol detail this layer owns.
     * Delegates to libsignal's HPKE via a small helper because the ECPublicKey
     * type lives in the client compile classpath but not in `protocol`.
     */
    private fun sealForGateway(publicKey: ByteArray, plaintext: ByteArray): ByteArray {
        val key = org.signal.libsignal.protocol.ecc.ECPublicKey(publicKey)
        return key.seal(plaintext, Protocol.OBLIVIOUS_INFO.toByteArray(Charsets.UTF_8), ByteArray(0))
    }

    private fun get(path: String, auth: Boolean = false): Response = execute("GET", path, null, auth)

    private fun post(path: String, body: JSONObject): Response =
        execute("POST", path, body.toString().toRequestBody(JSON_MEDIA), auth = false)

    private fun put(path: String, body: JSONObject, auth: Boolean = false): Response =
        execute("PUT", path, body.toString().toRequestBody(JSON_MEDIA), auth)

    private fun execute(method: String, path: String, body: RequestBody?, auth: Boolean): Response {
        val builder = Request.Builder().url("$baseUrl$path").method(method, body)
        if (auth) builder.header("Authorization", "Bearer ${accessToken()}")
        return client.newCall(builder.build()).execute()
    }

    private fun checkStatus(response: Response) {
        if (response.isSuccessful) return
        throw failure(response.code, response.body?.string().orEmpty())
    }

    /** Parses a gateway refusal, keeping any detail it carried. */
    private fun failure(status: Int, text: String): TransportError {
        val parsed = runCatching { JSONObject(text) }.getOrNull()
        val code = parsed?.optString("error", "request_failed") ?: "request_failed"
        val difficulty = parsed?.optInt("difficulty", -1)?.takeIf { it >= 0 }
        return TransportError(status, code, difficulty)
    }

    private fun json(response: Response): JSONObject = response.use { res ->
        val text = res.body?.string().orEmpty()
        if (!res.isSuccessful) throw failure(res.code, text)
        // 204s have no body; a call site that treats null as "empty" would be
        // wrong here, so we return an empty object instead.
        if (text.isEmpty()) return JSONObject()
        JSONObject(text)
    }

    private fun urlEncode(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")

    /* ---- live delivery ---- */

    interface EnvelopeListener {
        fun onEnvelope(envelope: Envelope)
        /** The relay has nothing further queued right now. */
        fun onCaughtUp() {}
        fun onClosed(code: Int, reason: String) {}
        fun onFailure(cause: Throwable) {}
    }

    interface Subscription : Closeable

    /**
     * Opens the delivery socket. Every member of a bucket receives every
     * envelope sent to that bucket and discards what it cannot decrypt, so
     * this stream carries other people's mail by design — filtering happens
     * after decryption, never here.
     *
     * The bearer token travels in a header rather than the query string: URLs
     * end up in proxy logs and a token in a log is a token that has leaked.
     */
    fun connect(listener: EnvelopeListener): Subscription {
        val token = accessToken()
        val socketUrl = baseUrl.replaceFirst(Regex("^http"), "ws") + "/v1/socket"

        // A long-lived socket needs no read timeout, and needs pings so a
        // silently dropped connection is noticed rather than hanging forever.
        val socketClient = client.newBuilder()
            .readTimeout(Duration.ZERO)
            .pingInterval(Duration.ofSeconds(30))
            .build()

        val request = Request.Builder()
            .url(socketUrl)
            .header("Authorization", "Bearer $token")
            .build()

        val socket = socketClient.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                val parsed = runCatching { JSONObject(text) }.getOrNull() ?: return
                when (parsed.optString("type")) {
                    "envelope" -> {
                        val entry = parsed.optJSONObject("envelope") ?: return
                        val envelope = runCatching {
                            Envelope(
                                seq = entry.getLong("seq"),
                                content = Protocol.unb64(entry.getString("content")),
                                arrivedAt = entry.getLong("arrivedAt"),
                            )
                        }.getOrNull() ?: return
                        listener.onEnvelope(envelope)
                    }
                    "caught-up" -> listener.onCaughtUp()
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                listener.onClosed(code, reason)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                response?.close()
                listener.onFailure(t)
            }
        })

        return object : Subscription {
            override fun close() {
                socket.close(1000, "client closing")
            }
        }
    }

    companion object {
        private val JSON_MEDIA = "application/json".toMediaType()
    }
}
