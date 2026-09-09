package uz.millygram.client

import java.io.Closeable
import java.io.IOException
import java.time.Duration
import okhttp3.CertificatePinner
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
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
 * The one place in this module where an HTTP client is obtained.
 *
 * It exists because of a specific shape of bug: a security-relevant call that
 * takes `http: OkHttpClient = OkHttpClient()` gets the insecure client by
 * default, so the way to end up unprotected is to write nothing at all. That is
 * how recovery — the one unauthenticated flow that hands the client a trust
 * root — ended up running on a client the app had never configured, and how any
 * pinning added to the app's client would have quietly failed to cover it.
 * Funnelling every path through here means a change made once is a change made
 * everywhere, and a new call site has to name the client it wants.
 *
 * On what pinning actually buys here, honestly. This deployment reaches the
 * internet through a Tailscale Funnel on a `*.ts.net` name, and Tailscale
 * operates that zone: it can obtain a publicly-trusted certificate for the
 * hostname whenever it decides to. Pinning therefore defends against a passive
 * or active observer at the edge — a carrier-side proxy, an operator-installed
 * root on a handset, a mis-issuance by some unrelated CA — and not against the
 * party that runs the name. Pinning a leaf also breaks on renewal, which for an
 * app that people cannot easily update is an outage, not an inconvenience.
 * So the list ships empty: the honest posture is that there is no stable key
 * worth pinning until the deployment owns its own name and its own intermediate,
 * and shipping a pin we would have to rotate under pressure would be worse than
 * shipping none. The wiring is here so that turning it on later is a build
 * setting rather than a code change.
 */
object MillygramHttp {

    /**
     * Applies the configured pins, if any, to the client the caller supplied.
     *
     * Pins are applied to the gateway host and the relay host separately: they
     * are different names, often different operators, and a pin set that
     * silently covered only one of them would be the worst of both worlds — the
     * appearance of protection over the half that is left open.
     *
     * With an empty pin list this returns the caller's client untouched rather
     * than a rebuilt copy, so connection pools and interceptors the app set up
     * survive intact.
     */
    fun forGateway(
        base: OkHttpClient,
        serverUrl: String,
        obliviousRelayUrl: String?,
        certificatePins: List<String>,
    ): OkHttpClient {
        if (certificatePins.isEmpty()) return base

        val hosts = listOfNotNull(serverUrl, obliviousRelayUrl)
            .mapNotNull { it.toHttpUrlOrNull()?.host }
            .distinct()
        if (hosts.isEmpty()) return base

        val pinner = CertificatePinner.Builder()
            .apply {
                for (host in hosts) {
                    for (pin in certificatePins) add(host, pin)
                }
            }
            .build()
        return base.newBuilder().certificatePinner(pinner).build()
    }
}

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
    /**
     * Every real caller passes the client the app configured, obtained through
     * [MillygramHttp.forGateway]. The default here is reached only by the JVM
     * shape tests, which talk to a MockWebServer on loopback and have nothing
     * to pin; it is deliberately not offered to any production path, because a
     * defaulted client on a security-relevant call is how the unconfigured one
     * becomes the one you get by writing nothing.
     */
    private val client: OkHttpClient = OkHttpClient.Builder().build(),
    /**
     * Supplies the environment signal at auth time. A supplier rather than a
     * fixed string because the answer can change during a session — a debugger
     * or hook can attach after launch — so it is read fresh on each token
     * refresh, not captured once at construction.
     */
    private val environment: (() -> String)? = null,
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

    data class RegisterResponse(
        val aci: String,
        val bucketId: Long,
        val trustRoot: String,
        val powDifficulty: Int,
        /** Base64 of this account's own avatar seed. Empty on an older gateway. */
        val avatarSeed: String,
    )

    fun register(request: JSONObject): RegisterResponse {
        val body = json(post("/v1/accounts", request))
        return RegisterResponse(
            aci = body.getString("aci"),
            bucketId = body.getLong("bucketId"),
            avatarSeed = body.optString("avatarSeed", ""),
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
            environment?.invoke()?.let { put("environment", it) }
        }))

        val newToken = Token(response.getString("token"), response.getLong("expiresAt"))
        token = newToken
        return newToken.value
    }

    /* ---- directory and keys ---- */

    data class DirectoryEntry(
        val aci: String,
        val deviceId: Int,
        val bucketId: Long,
        /** Base64 of the gateway-assigned avatar seed. Empty on an older gateway. */
        val avatarSeed: String,
    )

    /**
     * Resolving a handle without disclosing it.
     *
     * The hash goes up, never the name. The gateway matches it against what it
     * stored at registration and learns which account was asked for — but not
     * what that account is called, and not what the caller typed.
     */
    fun lookupUsername(username: String): DirectoryEntry {
        val hash = Protocol.b64(Handles.hash(username))
        val body = json(get("/v1/directory/${urlEncode(hash)}", auth = true))
        return DirectoryEntry(
            aci = body.getString("aci"),
            deviceId = body.getInt("deviceId"),
            bucketId = body.getLong("bucketId"),
            avatarSeed = body.optString("avatarSeed", ""),
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

    /* ---- recovery ---- */

    fun attachRecoveryNumber(phoneNumber: String) {
        json(put("/v1/account/recovery-number", JSONObject().apply { put("phoneNumber", phoneNumber) }, auth = true))
    }

    fun detachRecoveryNumber() {
        execute("DELETE", "/v1/account/recovery-number", null, auth = true).use { checkStatus(it) }
    }

    /**
     * Recovery runs before there is an account, so it cannot borrow an
     * authenticated [Transport] and has to be given a client of its own.
     *
     * That client is a required argument on both calls below, with no default,
     * and the omission is the point. These two requests are the most sensitive
     * unauthenticated exchange the app makes — one carries a phone number that
     * in this country is registered against a passport, the other comes back
     * with the trust root the client will pin for the life of the install — and
     * they used to default to `OkHttpClient()`, a client the app had never
     * configured and could never configure. A defaulted client on a call like
     * this is a trap: it makes the insecure path the one you get by writing
     * nothing, and any pinning or interception the app arranged for its own
     * client would have silently failed to cover exactly the flow that needed
     * it most. Making the parameter required means a new call site has to say,
     * out loud, which client it is using.
     */
    object Recovery {
        private val JSON_MEDIA_TYPE = "application/json".toMediaType()

        /**
         * Asks for a code, on a transport with no account behind it.
         *
         * Answers the same whether or not the number is known, so there is
         * nothing here to read: a client cannot learn from this call whether
         * somebody uses the service, and neither can anyone watching it.
         */
        fun start(baseUrl: String, phoneNumber: String, http: OkHttpClient) {
            val body = JSONObject().apply { put("phoneNumber", phoneNumber) }
            val request = Request.Builder()
                .url("$baseUrl/v1/recovery/start".toHttpUrl())
                .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
                .build()
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw TransportError(response.code, "recovery_start_failed")
                }
            }
        }

        fun complete(baseUrl: String, body: JSONObject, http: OkHttpClient): JSONObject {
            val request = Request.Builder()
                .url("$baseUrl/v1/recovery/complete".toHttpUrl())
                .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
                .build()
            http.newCall(request).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    val code = runCatching { JSONObject(text).optString("error", "request_failed") }
                        .getOrDefault("request_failed")
                    throw TransportError(response.code, code)
                }
                return JSONObject(text)
            }
        }
    }

    /* ---- messages ---- */

    /**
     * Solves the proof of work and submits the envelope. When configured with
     * an oblivious relay, the whole request is sealed to the gateway's key
     * and forwarded through it, so the gateway never sees this device's
     * address. Without the relay it goes straight to the gateway, still
     * anonymous in every other respect.
     */
    /**
     * Hands one envelope to the gateway, paying whatever the bucket costs now.
     *
     * A bucket whose shared inbound budget is being drained charges extra work
     * and names the figure when it refuses. Submission is anonymous, so the
     * gateway has no sender to throttle and the price is the only lever it has;
     * without this retry an honest sender reads that price as a flat refusal,
     * and the flooder still wins.
     *
     * Once. A second raise inside one send means the bucket is draining faster
     * than a handset can answer, and paying without limit turns the sender into
     * the flooder's battery.
     */
    fun submit(bucketId: Long, content: ByteArray, difficulty: Int) {
        var required = difficulty
        var attempt = 0
        while (true) {
            try {
                submitSolved(bucketId, content, Protocol.solveProofOfWork(bucketId, content, required))
                return
            } catch (failure: TransportError) {
                val asked = failure.requiredDifficulty
                val harder = failure.code == "insufficient_proof_of_work" && asked != null && asked > required
                if (!harder || attempt > 0) throw failure
                required = asked!!
                attempt += 1
            }
        }
    }

    private fun submitSolved(bucketId: Long, content: ByteArray, nonce: Long) {
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
        // A body that is not a JSON object at all — the four characters `null`
        // are enough — makes JSONObject throw, and that lands here rather than
        // in the per-entry guard below. The result is the very outcome that
        // guard exists to prevent: catch-up raises, the cursor does not move,
        // and the app sits there saying it is online. The TypeScript client
        // returns an empty list for the same input, so throwing here would also
        // be a disagreement between the two implementations about what a
        // hostile gateway can do.
        //
        // Only the parse is forgiven. A transport failure still propagates,
        // because a 401 has to reach the code that refreshes the token.
        val response = get("/v1/messages?since=$cursor", auth = true)
        val body = try {
            json(response)
        } catch (e: TransportError) {
            throw e
        } catch (t: Throwable) {
            return emptyList()
        }
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
