package uz.millygram.client

import android.content.Context
import java.io.Closeable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.UUID
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.signal.libsignal.metadata.ProtocolUntrustedIdentityException
import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.signal.libsignal.metadata.certificate.SenderCertificate
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import uz.millygram.protocol.Protocol

/** How to reach a gateway and which local vault to use. */
data class MillygramOptions(
    val context: Context,
    val databaseName: String,
    val passphrase: String,
    val serverUrl: String,
    val obliviousRelayUrl: String? = null,
    val http: OkHttpClient = OkHttpClient.Builder().build(),
)

data class MillygramRegisterOptions(val username: String, val base: MillygramOptions)

/**
 * The messenger facade. Registration produces an account whose long-lived
 * secrets never leave the device; open reopens one; send and receive move
 * text through the sealed-sender pipeline that lets the relay carry ciphertext
 * without ever learning its ends.
 *
 * This is the Android analogue of `packages/client/src/index.ts`. The wire
 * protocol is pinned against the TypeScript reference by the conformance
 * vectors in `:protocol`; anything that changes here without changing the
 * vectors is a divergence bug.
 */
class MillygramClient private constructor(
    private val store: LocalStore,
    private val stores: ProtocolStores,
    private val combined: CombinedProtocolStore,
    private val transport: Transport,
    private val identity: IdentityKeyPair,
    val aci: String,
    val username: String,
    val deviceId: Int,
    val bucketId: Long,
    private val powDifficulty: Int,
    private val trustRoot: ECPublicKey,
) : Closeable {

    /** Bounded cache to avoid a network round-trip on every send. */

    /**
     * Single worker so envelope handling — and therefore the cursor — is
     * strictly serialised regardless of which thread OkHttp delivers on.
     */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "millygram-envelopes").apply { isDaemon = true }
    }

    @Volatile
    private var closed = false

    override fun close() {
        closed = true
        worker.shutdown()
        store.close()
    }

    /**
     * Envelope work is submitted from OkHttp's socket thread, which can deliver
     * after close() has already shut the executor down. Submitting then throws
     * RejectedExecutionException out of a callback with no handler, taking the
     * process with it. Dropping late work is correct: the store it would write
     * to is closed.
     */
    private fun submitWork(task: () -> Unit) {
        if (closed) return
        try {
            worker.execute {
                if (!closed) task()
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            // close() raced us. Nothing to do; the vault is gone.
        }
    }

    /* ---- application storage ---- */

    /**
     * A small namespaced area of the encrypted vault for the layer above.
     *
     * The app needs somewhere to keep things like which username belongs to
     * which account id, and a contact list is exactly the sort of thing that
     * must not sit in plain SharedPreferences. Namespacing keeps it from
     * colliding with protocol state, and it inherits the vault's per-row AAD
     * binding for free.
     */
    fun putAppData(key: String, value: String) = store.setMetaString("app:$key", value)

    fun getAppData(key: String): String? = store.getMetaString("app:$key")

    /* ---- account discovery ---- */

    fun resolveUsername(name: String): Transport.DirectoryEntry {
        val entry = transport.lookupUsername(name)
        store.setMetaLong(peerBucketMeta(entry.aci), entry.bucketId)
        return entry
    }

    /* ---- session setup ---- */

    private fun localAddress(): SignalProtocolAddress = SignalProtocolAddress(aci, deviceId)

    /**
     * Establishes a session from a published prekey bundle. Signatures are
     * checked here as well as at the relay — a client that trusted the
     * server's verification would have no protection against the server.
     */
    private fun ensureSession(peerAci: String, peerDeviceId: Int): SignalProtocolAddress {
        val address = SignalProtocolAddress(peerAci, peerDeviceId)
        if (stores.session.containsSession(address)) return address

        val bundle = transport.fetchPreKeyBundle(peerAci)
        val identityKey = IdentityKey(Protocol.unb64(bundle.getString("identityKey")), 0)

        val signedPreKey = bundle.getJSONObject("signedPreKey")
        val signedPreKeyPublic = ECPublicKey(Protocol.unb64(signedPreKey.getString("publicKey")))
        val signedPreKeySignature = Protocol.unb64(signedPreKey.getString("signature"))
        require(identityKey.publicKey.verifySignature(signedPreKeyPublic.serialize(), signedPreKeySignature)) {
            "signed prekey for $peerAci is not signed by the advertised identity key"
        }

        val kyberPreKey = bundle.getJSONObject("kyberPreKey")
        val kyberPreKeyPublic = KEMPublicKey(Protocol.unb64(kyberPreKey.getString("publicKey")))
        val kyberPreKeySignature = Protocol.unb64(kyberPreKey.getString("signature"))
        require(identityKey.publicKey.verifySignature(kyberPreKeyPublic.serialize(), kyberPreKeySignature)) {
            "kyber prekey for $peerAci is not signed by the advertised identity key"
        }

        val oneTime = bundle.optJSONObject("oneTimePreKey")
        val oneTimeId = oneTime?.getInt("keyId") ?: PreKeyBundle.NULL_PRE_KEY_ID
        val oneTimeKey = oneTime?.let { ECPublicKey(Protocol.unb64(it.getString("publicKey"))) }

        val preKeyBundle = PreKeyBundle(
            bundle.getInt("registrationId"),
            bundle.getInt("deviceId"),
            oneTimeId,
            oneTimeKey,
            signedPreKey.getInt("keyId"),
            signedPreKeyPublic,
            signedPreKeySignature,
            identityKey,
            kyberPreKey.getInt("keyId"),
            kyberPreKeyPublic,
            kyberPreKeySignature,
        )

        SessionBuilder(
            stores.session,
            stores.preKey,
            stores.signedPreKey,
            stores.identity,
            address,
            localAddress(),
        ).process(preKeyBundle)

        // Remember where to answer, so that a later send never asks the relay.
        store.setMetaLong(peerBucketMeta(peerAci), bundle.getLong("bucketId"))
        return address
    }

    /* ---- delivery certificate ---- */

    private fun deliveryCertificate(): SenderCertificate {
        val cached = store.getMeta(META_SENDER_CERT)
        val expiresAt = store.getMetaLong(META_SENDER_CERT_EXPIRY)
        if (cached != null && expiresAt != null && expiresAt - 60_000 > System.currentTimeMillis()) {
            return SenderCertificate(cached)
        }

        val fetched = transport.fetchDeliveryCertificate()
        val certificate = SenderCertificate(Protocol.unb64(fetched.certificate))

        CertificateValidator(trustRoot).validate(certificate, System.currentTimeMillis())

        store.setMeta(META_SENDER_CERT, certificate.serialized)
        store.setMetaLong(META_SENDER_CERT_EXPIRY, fetched.expiresAt)
        return certificate
    }

    /* ---- send / receive ---- */

    fun send(recipient: String, body: String) {
        require(body.isNotEmpty()) { "message body is empty" }
        require(body.toByteArray(Charsets.UTF_8).size <= Protocol.MAX_PLAINTEXT_BYTES) {
            "message body exceeds ${Protocol.MAX_PLAINTEXT_BYTES} bytes"
        }

        val target = if (Protocol.isValidUsername(recipient)) resolveUsername(recipient)
        else Transport.DirectoryEntry(
            aci = recipient,
            deviceId = Protocol.DEVICE_ID_PRIMARY,
            bucketId = store.getMetaLong(peerBucketMeta(recipient))
                ?: throw IllegalStateException("no delivery bucket known for $recipient"),
        )

        // Everything from here on reads and writes the session record, and the
        // Double Ratchet is read-modify-write: two sends that interleave both
        // encrypt from the same state and the second write discards the first's
        // ratchet advance. Both sends report success, the relay accepts both
        // envelopes, and the recipient can only follow one chain — so one
        // message is silently undeliverable. Running on the same single thread
        // that consumes envelopes keeps every mutation of that record in one
        // order, which also covers a send racing an incoming message.
        exclusive {
            val address = ensureSession(target.aci, target.deviceId)

            val payload = JSONObject().apply {
                put("v", 1)
                put("body", body)
                put("sentAt", System.currentTimeMillis())
                put("bucketId", bucketId)
            }.toString().toByteArray(Charsets.UTF_8)

            val cipher = SealedSessionCipher(combined, UUID.fromString(aci), null, deviceId)
            val sealed = cipher.encrypt(address, deliveryCertificate(), payload)

            val padded = Protocol.pad(sealed)
            transport.submit(target.bucketId, padded, powDifficulty)
        }
    }

    /**
     * Runs a task on the delivery thread and waits for it, unwrapping the
     * failure so callers still see the original exception. Called from the
     * delivery thread itself this would deadlock, so it never is.
     */
    private fun <T> exclusive(task: () -> T): T {
        check(!closed) { "client is closed" }
        val future = try {
            worker.submit(java.util.concurrent.Callable { task() })
        } catch (rejected: java.util.concurrent.RejectedExecutionException) {
            throw IllegalStateException("client is closed", rejected)
        }
        return try {
            future.get()
        } catch (failed: java.util.concurrent.ExecutionException) {
            throw failed.cause ?: failed
        }
    }

    data class IncomingMessage(
        val senderAci: String,
        val senderDeviceId: Int,
        val body: String,
        val sentAt: Long,
        val receivedAt: Long,
    )

    /**
     * Forgets everything pinned about a contact: the session and the identity
     * key.
     *
     * This is the only way out of an identity change. Until it is called the
     * old key stays pinned, so every message the contact sends is rejected and
     * the conversation is dead in both directions — correct when someone is
     * substituting keys, wrong when the contact simply reinstalled, which is
     * the far commoner case. The next message re-establishes from a fresh
     * bundle and pins whatever it carries, so this returns the conversation to
     * trust on first use and must be an explicit choice by someone who has
     * looked at the safety number, never something the client decides.
     */
    fun forgetPeer(peerAci: String) {
        exclusive {
            val address = "$peerAci.${Protocol.DEVICE_ID_PRIMARY}"
            store.deleteRecord("sessions", address)
            store.deleteRecord("identities", address)
        }
    }

    /**
     * Called when an envelope arrives from a contact whose pinned identity key
     * no longer matches. Set it before [connect]; it is invoked on the
     * delivery thread, so implementations must not block.
     *
     * This is the client's only channel for reporting key substitution, and a
     * caller that leaves it unset is choosing not to be told.
     */
    @Volatile
    var onIdentityMismatch: ((senderAci: String) -> Unit)? = null

    /**
     * Sealed sender wraps protocol exceptions, so matching on the outermost
     * type alone would miss the wrapped case and silently lose the alarm.
     */
    private fun untrustedSender(failure: Throwable): String? {
        var cause: Throwable? = failure
        while (cause != null) {
            when (cause) {
                is ProtocolUntrustedIdentityException -> return cause.sender
                is UntrustedIdentityException -> return cause.name
            }
            cause = cause.cause
        }
        return null
    }

    /**
     * Bucket members receive every envelope sent to the bucket. Anything not
     * addressed to us fails to open and is dropped without a word — that
     * silence is what stops the relay from learning who a message was for.
     */
    fun openEnvelope(envelope: Transport.Envelope): IncomingMessage? {
        val unpadded = try {
            Protocol.unpad(envelope.content)
        } catch (_: Throwable) {
            return null
        }

        val cipher = SealedSessionCipher(combined, UUID.fromString(aci), null, deviceId)
        val validator = CertificateValidator(trustRoot)
        val result = try {
            cipher.decrypt(validator, unpadded, System.currentTimeMillis())
        } catch (failure: Throwable) {
            // Almost every failure here is an envelope addressed to another
            // member of the bucket, and that silence is load-bearing: it is
            // what stops the relay learning who a message was for.
            //
            // Exactly one failure means something else. If the envelope opened
            // far enough to name a sender whose identity key we had already
            // pinned, and the key does not match, that is what a relay
            // substituting keys looks like from inside the client. Dropping it
            // into the same silence would make pinning pointless — the attack
            // would be indistinguishable from ordinary bucket noise, and the
            // message would simply vanish. So this one is reported.
            untrustedSender(failure)?.let { onIdentityMismatch?.invoke(it) }
            return null
        }

        val body = runCatching {
            val json = JSONObject(String(result.paddedMessage, Charsets.UTF_8))
            IncomingMessage(
                senderAci = result.senderUuid,
                senderDeviceId = result.deviceId,
                body = json.getString("body"),
                sentAt = json.getLong("sentAt"),
                receivedAt = System.currentTimeMillis(),
            ).also { message ->
                // First value wins, and a later message can never change it.
                // This field is attacker-controlled: a peer able to rewrite it
                // could point our replies at any bucket they chose, making every
                // member of that bucket download traffic they never asked for.
                if (store.getMetaLong(peerBucketMeta(message.senderAci)) == null) {
                    store.setMetaLong(peerBucketMeta(message.senderAci), json.getLong("bucketId"))
                }
            }
        }.getOrNull()

        return body
    }

    /**
     * Applies one envelope and advances the cursor. Every path that consumes
     * envelopes funnels through here on a single worker thread, because the
     * cursor is read-modify-write: live delivery and catch-up racing each other
     * would either skip a message or replay one.
     */
    private fun consume(envelope: Transport.Envelope, onMessage: (IncomingMessage) -> Unit) {
        if (envelope.seq <= (store.getMetaLong(META_CURSOR) ?: 0)) return
        val message = openEnvelope(envelope)
        store.setMetaLong(META_CURSOR, envelope.seq)
        if (message != null) onMessage(message)
    }

    /** Collects anything that has arrived in the bucket since the last cursor. */
    fun catchUp(onMessage: (IncomingMessage) -> Unit) {
        val envelopes = transport.since(store.getMetaLong(META_CURSOR) ?: 0)
        for (envelope in envelopes) {
            if (closed) return
            worker.submit { consume(envelope, onMessage) }.get()
        }
    }

    /**
     * Opens the live delivery socket and drains anything missed while offline.
     * The returned handle closes the socket; the client itself stays usable.
     */
    fun connect(
        onMessage: (IncomingMessage) -> Unit,
        onDisconnected: (() -> Unit)? = null,
    ): Closeable {
        val subscription = transport.connect(object : Transport.EnvelopeListener {
            override fun onEnvelope(envelope: Transport.Envelope) {
                submitWork { consume(envelope, onMessage) }
            }

            override fun onCaughtUp() {
                submitWork { runCatching { replenishPreKeys() } }
            }

            // The socket does not come back on its own, and the transport
            // already notices a silent drop through its ping interval. Both
            // ends are forwarded so the owner can reconnect; without this the
            // client stays offline and says nothing after the first blip,
            // which on a mobile network is a matter of minutes.
            override fun onClosed(code: Int, reason: String) {
                onDisconnected?.invoke()
            }

            override fun onFailure(cause: Throwable) {
                onDisconnected?.invoke()
            }
        })

        // Anything that arrived while this device was away is not replayed over
        // the socket, so the gap is closed explicitly on connect.
        submitWork {
            runCatching {
                for (envelope in transport.since(store.getMetaLong(META_CURSOR) ?: 0)) {
                    consume(envelope, onMessage)
                }
            }
        }

        return subscription
    }

    /* ---- safety numbers ---- */

    /**
     * The number both parties compare out of band. Derived only from the two
     * identity keys, so a relay that swapped either one cannot make the two
     * sides compute the same value.
     */
    fun safetyNumber(peerAci: String): String {
        val peer = stores.identity.getIdentity(SignalProtocolAddress(peerAci, Protocol.DEVICE_ID_PRIMARY))
            ?: throw IllegalStateException("no identity key stored for $peerAci; exchange a message first")

        val generator = NumericFingerprintGenerator(SAFETY_NUMBER_ITERATIONS)
        val fingerprint = generator.createFor(
            SAFETY_NUMBER_VERSION,
            aci.toByteArray(Charsets.UTF_8),
            identity.publicKey,
            peerAci.toByteArray(Charsets.UTF_8),
            peer,
        )
        return fingerprint.displayableFingerprint.displayText
    }

    /* ---- prekey replenishment ---- */

    fun replenishPreKeys() {
        val remaining = try {
            transport.remainingOneTimePreKeys()
        } catch (_: TransportError) {
            return
        }
        if (remaining > Protocol.ONE_TIME_PREKEY_LOW_WATER) return

        val firstId = store.getMetaLong(META_NEXT_PREKEY_ID)?.toInt() ?: (Protocol.ONE_TIME_PREKEY_BATCH + 1)
        val count = Protocol.ONE_TIME_PREKEY_BATCH - remaining
        val generated = Keys.generateOneTimePreKeys(firstId, count, stores)

        transport.replenishKeys(JSONObject().apply { put("oneTimePreKeys", generated.toJsonArray()) })
        store.setMetaLong(META_NEXT_PREKEY_ID, (firstId + count).toLong())
    }

    /* ---- internals ---- */



    companion object {

        private const val META_IDENTITY = "identity"
        private const val META_REGISTRATION_ID = "registrationId"
        private const val META_ACI = "aci"
        private const val META_USERNAME = "username"
        private const val META_DEVICE_ID = "deviceId"
        private const val META_BUCKET_ID = "bucketId"
        private const val META_POW_DIFFICULTY = "powDifficulty"
        private const val META_TRUST_ROOT = "trustRoot"
        private const val META_SENDER_CERT = "senderCert"
        private const val META_SENDER_CERT_EXPIRY = "senderCertExpiresAt"
        private const val META_NEXT_PREKEY_ID = "nextPreKeyId"
        private const val META_CURSOR = "bucketCursor"

        private fun peerBucketMeta(aci: String): String = "peerBucket:$aci"

        private const val SAFETY_NUMBER_ITERATIONS = 5200
        private const val SAFETY_NUMBER_VERSION = 2

        fun register(options: MillygramRegisterOptions): MillygramClient {
            require(Protocol.isValidUsername(options.username)) {
                "username must be 3-32 characters of a-z, 0-9 or underscore"
            }

            val store = LocalStore.open(options.base.context, options.base.databaseName, options.base.passphrase)
            if (store.getMeta(META_ACI) != null) {
                store.close()
                throw IllegalStateException(
                    "this database already holds an account; open it instead of registering",
                )
            }

            val identity = IdentityKeyPair.generate()
            val registrationId = Keys.generateRegistrationId()

            store.setMeta(META_IDENTITY, identity.serialize())
            store.setMetaLong(META_REGISTRATION_ID, registrationId.toLong())
            store.setMetaLong(META_DEVICE_ID, Protocol.DEVICE_ID_PRIMARY.toLong())
            store.setMetaString(META_USERNAME, options.username)

            val stores = ProtocolStores.forAccount(store, identity, registrationId)
            val combined = CombinedProtocolStore(stores)

            val signedPreKey = Keys.generateSignedPreKey(identity, 1, stores)
            val kyberPreKey = Keys.generateKyberPreKey(identity, 1, stores)
            val oneTimePreKeys = Keys.generateOneTimePreKeys(1, Protocol.ONE_TIME_PREKEY_BATCH, stores)
            store.setMetaLong(META_NEXT_PREKEY_ID, (Protocol.ONE_TIME_PREKEY_BATCH + 1).toLong())

            val timestamp = System.currentTimeMillis()
            val signPayload = Protocol.registrationSigningPayload(
                username = options.username,
                deviceId = Protocol.DEVICE_ID_PRIMARY.toLong(),
                registrationId = registrationId.toLong(),
                identityKey = identity.publicKey.serialize(),
                signedPreKeyId = signedPreKey.keyId.toLong(),
                signedPreKeyPublic = Protocol.unb64(signedPreKey.publicKeyB64),
                kyberPreKeyId = kyberPreKey.keyId.toLong(),
                kyberPreKeyPublic = Protocol.unb64(kyberPreKey.publicKeyB64),
                timestamp = timestamp,
            )
            val signature = identity.privateKey.calculateSignature(signPayload)

            val body = JSONObject().apply {
                put("username", options.username)
                put("deviceId", Protocol.DEVICE_ID_PRIMARY)
                put("registrationId", registrationId)
                put("identityKey", Protocol.b64(identity.publicKey.serialize()))
                put("signedPreKey", signedPreKey.toJson())
                put("kyberPreKey", kyberPreKey.toJson())
                put("oneTimePreKeys", oneTimePreKeys.toJsonArray())
                put("timestamp", timestamp)
                put("signature", Protocol.b64(signature))
            }

            val transport = Transport(
                baseUrl = options.base.serverUrl,
                credentials = null,
                obliviousRelayUrl = options.base.obliviousRelayUrl,
                client = options.base.http,
            )

            // Registration is charged in CPU rather than to an address. Every
            // user on an Uzbek mobile network shares a handful of public
            // addresses, so an address-based limit would ration signups for a
            // whole carrier; work costs the same wherever it is solved. The
            // retry exists so the gateway can raise the price during a flood
            // without every installed client breaking.
            val registered = try {
                var difficulty = Protocol.REGISTRATION_POW_DIFFICULTY
                var attempt = 0
                var result: Transport.RegisterResponse? = null
                while (result == null) {
                    body.put("workNonce", Protocol.solveRegistrationWork(signPayload, difficulty))
                    try {
                        result = transport.register(body)
                    } catch (failure: TransportError) {
                        val harder = failure.code == "work_required" &&
                            failure.requiredDifficulty != null &&
                            failure.requiredDifficulty > difficulty
                        if (!harder || attempt > 0) throw failure
                        difficulty = failure.requiredDifficulty
                        attempt += 1
                    }
                }
                result
            } catch (t: Throwable) {
                store.close()
                throw t
            }

            store.setMetaString(META_ACI, registered.aci)
            store.setMetaString(META_TRUST_ROOT, registered.trustRoot)
            store.setMetaLong(META_BUCKET_ID, registered.bucketId)
            store.setMetaLong(META_POW_DIFFICULTY, registered.powDifficulty.toLong())

            val trustRootKey = ECPublicKey(Protocol.unb64(registered.trustRoot))
            transport.setCredentials(SigningCredentials(registered.aci, Protocol.DEVICE_ID_PRIMARY, identity))

            return MillygramClient(
                store, stores, combined, transport, identity,
                registered.aci, options.username, Protocol.DEVICE_ID_PRIMARY,
                registered.bucketId, registered.powDifficulty, trustRootKey,
            )
        }

        fun open(options: MillygramOptions): MillygramClient {
            val store = LocalStore.open(options.context, options.databaseName, options.passphrase)

            val identityRaw = store.getMeta(META_IDENTITY)
            val aci = store.getMetaString(META_ACI)
            val username = store.getMetaString(META_USERNAME)
            val registrationId = store.getMetaLong(META_REGISTRATION_ID)?.toInt()
            val deviceId = store.getMetaLong(META_DEVICE_ID)?.toInt()
            val bucketId = store.getMetaLong(META_BUCKET_ID)
            val powDifficulty = store.getMetaLong(META_POW_DIFFICULTY)?.toInt()
            val trustRoot = store.getMetaString(META_TRUST_ROOT)

            require(identityRaw != null && aci != null && username != null && trustRoot != null &&
                registrationId != null && deviceId != null && bucketId != null && powDifficulty != null) {
                store.close()
                "this database does not hold a complete account"
            }

            val identity = IdentityKeyPair(identityRaw)
            val stores = ProtocolStores.forAccount(store, identity, registrationId)
            val combined = CombinedProtocolStore(stores)

            val transport = Transport(
                baseUrl = options.serverUrl,
                credentials = SigningCredentials(aci, deviceId, identity),
                obliviousRelayUrl = options.obliviousRelayUrl,
                client = options.http,
            )

            return MillygramClient(
                store, stores, combined, transport, identity,
                aci, username, deviceId, bucketId, powDifficulty,
                ECPublicKey(Protocol.unb64(trustRoot)),
            )
        }
    }
}

/** The transport's credential contract, satisfied by an identity private key. */
private class SigningCredentials(
    override val aci: String,
    override val deviceId: Int,
    private val identity: IdentityKeyPair,
) : Credentials {
    override fun sign(payload: ByteArray): ByteArray = identity.privateKey.calculateSignature(payload)
}

