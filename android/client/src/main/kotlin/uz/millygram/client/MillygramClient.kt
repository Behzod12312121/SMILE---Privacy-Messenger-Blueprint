package uz.millygram.client

import android.content.Context
import java.io.Closeable
import java.security.MessageDigest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.UUID
import okhttp3.OkHttpClient
import org.json.JSONArray
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
    /**
     * SPKI pins, in OkHttp's `sha256/…` form, applied to the gateway and relay
     * hosts. Empty means the platform trust store alone decides, which is what
     * ships today; see [MillygramHttp] for why there is nothing worth pinning
     * to a Tailscale Funnel name and what turning this on would and would not
     * buy. The layer above supplies the list, because the deployment it points
     * at is a build-time fact this module has no way to know.
     */
    val certificatePins: List<String> = emptyList(),
    /**
     * The trust root this build expects the gateway to hand it, base64 as it
     * appears on the wire.
     *
     * The trust root is the key that says which sender certificates are
     * genuine, so it decides whose authorship the app will believe. Registration
     * and recovery both learn it from the server's answer and pin it for the
     * life of the install — which means that on the one occasion the client has
     * no account and no pinned key, whoever answers the request chooses it. An
     * attacker who can answer /v1/recovery/complete once owns sealed-sender
     * authorship forever after, silently, on a handset that will never be asked
     * about it again.
     *
     * Setting this turns that from trust-on-first-answer into a check. Null
     * keeps the old behaviour, because a build that does not know its gateway's
     * root cannot invent one, and refusing to register would be worse than the
     * exposure. A shipped build should set it.
     */
    val expectedTrustRoot: String? = null,
    /**
     * Whether to send the tamper signal to the gateway on authentication.
     *
     * Off, and off is the honest default. Every check behind that string is
     * defeatable — Magisk hides its own mounts, Frida can be renamed, the maps
     * can be scrubbed — so an attacker reports "clean" and is believed. The
     * person the signal reliably identifies is an ordinary user on a rooted or
     * unusual handset, and in this market that is a large share of real users:
     * a cheap phone with a vendor ROM, a second-hand device somebody rooted
     * years ago, a build sideloaded because the store is awkward to reach. What
     * the gateway ends up holding is a durable per-device fingerprint sitting
     * next to the account id, which is precisely the record this project exists
     * not to create — and it is a record of the honest, since the dishonest do
     * not appear in it. The collection stays, because a user is entitled to see
     * it about their own device, and an operator who has weighed the trade can
     * turn it on. Volunteering it was the mistake.
     */
    val reportEnvironment: Boolean = false,
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
    private val appContext: android.content.Context,
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
        rememberAvatarSeed(entry.aci, entry.avatarSeed)
        return entry
    }

    /**
     * Caches the avatar seed the gateway published for an account.
     *
     * Only ever called with a value that arrived from the gateway. There is
     * deliberately no path from a message payload to here: an avatar a peer
     * could set would be bytes one user gets to choose on another user's
     * screen, which is the thing this app refuses to have.
     */
    private fun rememberAvatarSeed(peerAci: String, b64Seed: String) {
        if (b64Seed.isEmpty()) return
        val bytes = runCatching { Protocol.unb64(b64Seed) }.getOrNull() ?: return
        if (bytes.isEmpty() || bytes.size > 64) return
        store.setMetaString(peerAvatarMeta(peerAci), b64Seed)
    }

    /** The avatar seed known for an account, or null before its keys are fetched. */
    fun avatarSeed(peerAci: String): ByteArray? =
        store.getMetaString(peerAvatarMeta(peerAci))
            ?.takeIf { it.isNotEmpty() }
            ?.let { runCatching { Protocol.unb64(it) }.getOrNull() }

    /** This account's own seed, so the profile row shows what everyone else sees. */
    val ownAvatarSeed: ByteArray?
        get() = avatarSeed(aci)

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
        rememberAvatarSeed(peerAci, bundle.optString("avatarSeed", ""))
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

    fun send(recipient: String, body: String) = sendPayload(recipient, body, null, null)

    /**
     * The single path every outgoing message takes, private or group.
     *
     * A group message is an ordinary sealed-sender envelope carrying a group
     * identifier inside the ciphertext. Nothing on the wire differs — same
     * size, same bucket, same padding — so the gateway cannot separate group
     * traffic from private traffic, or tell two groups apart.
     */
    private fun sendPayload(
        recipient: String,
        body: String,
        groupId: String?,
        control: JSONObject?,
    ) {
        require(body.isNotEmpty()) { "message body is empty" }
        require(body.toByteArray(Charsets.UTF_8).size <= Protocol.MAX_PLAINTEXT_BYTES) {
            "message body exceeds ${Protocol.MAX_PLAINTEXT_BYTES} bytes"
        }

        val target = if (Handles.isValidUsername(recipient)) resolveUsername(recipient)
        else Transport.DirectoryEntry(
            aci = recipient,
            deviceId = Protocol.DEVICE_ID_PRIMARY,
            bucketId = store.getMetaLong(peerBucketMeta(recipient))
                ?: throw IllegalStateException("no delivery bucket known for $recipient"),
            // Already cached from the lookup that first resolved this account;
            // sending does not need it and must not go asking for it.
            avatarSeed = "",
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
                // Inside the ciphertext for the same reason the bucket is:
                // there is deliberately no way to ask the relay who owns an
                // identifier, so a first message from a stranger would
                // otherwise arrive with nothing to call them by.
                put("username", username)
                if (groupId != null) put("groupId", groupId)
                if (control != null) put("group", control)
            }.toString().toByteArray(Charsets.UTF_8)

            // Padded to a constant size before sealing, so the ciphertext
            // length -- which the envelope states in the clear, and every
            // bucket member reads -- stops tracking what was written. Checked
            // before the encrypt rather than after: Protocol.pad() raises this
            // once the ratchet has already advanced, spending a message key on
            // a send that then cannot leave.
            require(payload.size <= Protocol.PADDED_PAYLOAD_BYTES) {
                "message does not fit one envelope: ${payload.size} bytes of ${Protocol.PADDED_PAYLOAD_BYTES}"
            }

            val cipher = SealedSessionCipher(combined, UUID.fromString(aci), null, deviceId)
            val sealed = cipher.encrypt(address, deliveryCertificate(), Protocol.padPayload(payload))

            val padded = Protocol.pad(sealed)
            transport.submit(target.bucketId, padded, powDifficulty)
        }
    }

    /* ---- groups ---- */

    /** A group as this device understands it. Held here and nowhere else. */
    data class GroupState(
        val groupId: String,
        val name: String,
        val members: List<String>,
        val revision: Int,
    )

    /**
     * Creates a group and tells the members about it.
     *
     * The identifier is generated here and registered nowhere. Nothing in this
     * method asks the gateway anything beyond the ordinary sends, because a
     * group is not a thing the gateway has: it is a shared label a handful of
     * clients agree to put inside their ciphertext.
     */
    fun createGroup(name: String, memberAcis: List<String>): GroupState {
        require(name.isNotEmpty() && name.length <= Protocol.GROUP_NAME_MAX) {
            "a group name must be 1-" + Protocol.GROUP_NAME_MAX + " characters"
        }
        val members = (listOf(aci) + memberAcis).distinct()
        require(members.size <= Protocol.MAX_GROUP_MEMBERS) {
            "a group may hold at most " + Protocol.MAX_GROUP_MEMBERS + " members"
        }

        val raw = ByteArray(Protocol.GROUP_ID_BYTES).also { java.security.SecureRandom().nextBytes(it) }
        val group = GroupState(Protocol.b64(raw), name, members, 1)
        saveGroup(group)
        announceGroup(group, null)
        return group
    }

    /** Every group this device knows about. */
    fun groups(): List<GroupState> {
        val index = store.getMetaString(GROUP_INDEX) ?: return emptyList()
        val ids = runCatching { JSONArray(index) }.getOrNull() ?: return emptyList()
        return (0 until ids.length()).mapNotNull { group(ids.getString(it)) }
    }

    fun group(groupId: String): GroupState? {
        val raw = store.getMetaString(groupMeta(groupId))?.takeIf { it.isNotBlank() } ?: return null
        return runCatching {
            val o = JSONObject(raw)
            val m = o.getJSONArray("members")
            GroupState(
                groupId = o.getString("groupId"),
                name = o.getString("name"),
                members = (0 until m.length()).map { m.getString(it) },
                revision = o.getInt("revision"),
            )
        }.getOrNull()
    }

    /**
     * Sends to every member except this device.
     *
     * One padded envelope per member, because the gateway cannot fan a message
     * out to people it is not allowed to know about. That is the cost of the
     * property, and it is why the member cap exists.
     *
     * Deliberately not one ciphertext shared between members: each envelope is
     * its own ratchet step with its own forward secrecy, so removing somebody
     * takes effect on the very next message, with no key rotation to remember
     * and no window in which a removed member can still decrypt.
     */
    fun sendToGroup(groupId: String, body: String) {
        val group = group(groupId) ?: throw IllegalStateException("unknown group " + groupId)
        fanOut(group, body, null, null)
    }

    /** Adds or removes members and tells everyone, old and new. */
    fun updateGroupMembers(groupId: String, members: List<String>): GroupState {
        val existing = group(groupId) ?: throw IllegalStateException("unknown group " + groupId)
        val next = (listOf(aci) + members).distinct()
        require(next.size <= Protocol.MAX_GROUP_MEMBERS) {
            "a group may hold at most " + Protocol.MAX_GROUP_MEMBERS + " members"
        }
        val updated = existing.copy(members = next, revision = existing.revision + 1)
        saveGroup(updated)
        // The union of both lists: somebody just removed still receives the
        // notice that they were, which their client needs in order to stop
        // showing the group as live.
        announceGroup(updated, (existing.members + next).distinct())
        return updated
    }

    /** Leaves a group, tells the others, then forgets it locally. */
    fun leaveGroup(groupId: String) {
        val group = group(groupId) ?: return
        val remaining = group.members.filter { it != aci }
        val control = JSONObject().apply {
            put("name", group.name)
            put("members", JSONArray(remaining))
            put("event", "leave")
            put("revision", group.revision + 1)
        }
        fanOut(group.copy(members = remaining), "left", control, remaining)
        forgetGroup(groupId, group.revision + 1)
    }

    private fun announceGroup(group: GroupState, audience: List<String>?) {
        val control = JSONObject().apply {
            put("name", group.name)
            put("members", JSONArray(group.members))
            put("event", "update")
            put("revision", group.revision)
        }
        fanOut(group, "joined " + group.name, control, audience)
    }

    private fun fanOut(group: GroupState, body: String, control: JSONObject?, audience: List<String>?) {
        // One at a time, not in parallel: every send mutates a ratchet and the
        // worker that serialises them is per-client, so firing fifty at once
        // would only contend for it.
        for (member in (audience ?: group.members).filter { it != aci }) {
            sendPayload(member, body, group.groupId, control)
        }
    }

    /**
     * Merges a group description that arrived from another member.
     *
     * Worth writing down plainly: there is no server-side record of who is in a
     * group, so this is the only source of truth and it arrives from a peer. A
     * dishonest member can therefore claim any membership they like and every
     * client will believe them. That is a real limit of a design with no
     * authority to appeal to; closing it needs group changes signed by their
     * author and checked against the group history, which this does not yet
     * do. Until then the UI must show membership changes plainly, so a person
     * can notice one they did not expect.
     *
     * Revisions only move forward, so replaying an old announcement cannot
     * quietly restore a member who was removed.
     */
    private fun applyGroupUpdate(groupId: String, update: JSONObject, from: String) {
        // Read as a Long, because optInt truncates. A peer announcing
        // 2147483648 would otherwise arrive here as a negative number and be
        // dropped as malformed -- which is exactly the state an attacker wants,
        // since by then the stored revision is already at the 32-bit ceiling
        // and nothing honest can ever exceed it. Reading wide lets an
        // out-of-range value be recognised as hostile rather than mistaken for
        // corruption, and refused on its own terms.
        val wide = update.optLong("revision", -1L)
        if (wide < 0 || wide > Protocol.MAX_GROUP_REVISION) return
        // Safe to narrow only because the ceiling above is well inside Int.
        val revision = wide.toInt()
        val name = update.optString("name")
            .takeIf { it.isNotEmpty() && it.length <= Protocol.GROUP_NAME_MAX } ?: return
        val list = update.optJSONArray("members") ?: return
        val members = (0 until list.length()).map { list.getString(it) }
        if (members.isEmpty() || members.size > Protocol.MAX_GROUP_MEMBERS) return

        val existing = group(groupId)
        if (existing != null && revision <= existing.revision) return
        // Only somebody already in the group may change it, once we know of one.
        if (existing != null && from !in existing.members) return

        // A group we have left or been removed from leaves a tombstone, and the
        // tombstone is what keeps replay protection alive after the state it
        // protected is gone.
        //
        // Without it the attack is: remove somebody, wait for their client to
        // forget the group, then replay the original announcement. It arrives
        // with no existing state to compare against, so neither check above can
        // fire, and the group returns carrying whatever member list the
        // replayer chose — after which the victim sends group messages to
        // people the real owner never added.
        val tombstone = store.getMetaLong(groupTombstone(groupId))
        if (existing == null && tombstone != null && revision <= tombstone) return

        // An announcement from somebody absent from the membership they are
        // announcing is nonsense, and is how a stranger would introduce a group
        // built around a list of their choosing.
        if (from !in members && update.optString("event") != "leave") return

        if (update.optString("event") == "leave") {
            // A leave asserts one thing — the sender is gone — and is not an
            // announcement about the group. Treating it as one is what let a
            // stranger write a group onto this device: against an unknown
            // groupId there is no `existing`, so neither the revision check nor
            // the membership check above can fire, the exception on the line
            // above skips the last guard, and this branch then saved whatever
            // name, roster and revision arrived. The author needed no
            // relationship to the group at all.
            //
            // So a leave may only ever subtract its sender from a group we
            // already hold. Every other field comes from our own copy rather
            // than from the message, which also stops a real member rewriting
            // the roster or renaming the group on their way out.
            if (existing == null) return
            if (from !in existing.members) return
            saveGroup(
                GroupState(
                    groupId,
                    existing.name,
                    existing.members.filter { it != from },
                    revision,
                ),
            )
            return
        }
        if (aci !in members) {
            // No longer a member. Drop it rather than keep a group we can
            // neither send to nor ever receive from again.
            forgetGroup(groupId)
            return
        }

        // A group we have never seen is the only kind that grows this store,
        // and anybody who knows an account identifier can announce one. Without
        // a ceiling that is a device-filling attack from a single account.
        // Updates to groups already held are unaffected, so reaching the cap
        // cannot cost somebody a group they are really in.
        if (existing == null && groups().size >= Protocol.MAX_GROUPS) return

        saveGroup(GroupState(groupId, name, members, revision))
    }

    private fun saveGroup(group: GroupState) {
        store.setMetaString(
            groupMeta(group.groupId),
            JSONObject().apply {
                put("groupId", group.groupId)
                put("name", group.name)
                put("members", JSONArray(group.members))
                put("revision", group.revision)
            }.toString(),
        )
        val ids = linkedSetOf<String>()
        store.getMetaString(GROUP_INDEX)?.let { raw ->
            runCatching { JSONArray(raw) }.getOrNull()?.let { a ->
                (0 until a.length()).forEach { ids.add(a.getString(it)) }
            }
        }
        ids.add(group.groupId)
        store.setMetaString(GROUP_INDEX, JSONArray(ids.toList()).toString())
    }

    private fun forgetGroup(groupId: String, revision: Int? = null) {
        // Remember how far this group had got, so a replayed older announcement
        // cannot resurrect it. One integer per group ever left.
        val last = revision ?: group(groupId)?.revision
        if (last != null) {
            val prior = store.getMetaLong(groupTombstone(groupId)) ?: -1L
            if (last.toLong() > prior) store.setMetaLong(groupTombstone(groupId), last.toLong())
        }
        store.setMetaString(groupMeta(groupId), "")
        val ids = mutableListOf<String>()
        store.getMetaString(GROUP_INDEX)?.let { raw ->
            runCatching { JSONArray(raw) }.getOrNull()?.let { a ->
                (0 until a.length()).forEach { i ->
                    a.getString(i).takeIf { it != groupId }?.let(ids::add)
                }
            }
        }
        store.setMetaString(GROUP_INDEX, JSONArray(ids as List<String>).toString())
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
        /** What the sender says they are called. A claim; verify before trusting it. */
        val senderUsername: String?,
        val sentAt: Long,
        val receivedAt: Long,
        /** Set when this arrived in a group rather than a private thread. */
        val groupId: String? = null,
    )

    /**
     * Attaches a number so this account can be recovered on another handset.
     *
     * Never asked for at signup and never implied by it. What it costs is
     * specific and worth saying where the user can see it: a SIM in this
     * country is registered against a passport, so a gateway able to answer
     * "which account has this number" holds a link between an account and a
     * named person. That is a reasonable trade for somebody who expects to lose
     * a phone and a bad one for somebody who expects to be asked questions, and
     * only they can tell which they are.
     */
    fun attachRecoveryNumber(phoneNumber: String) = exclusive {
        require(Protocol.isValidPhoneNumber(phoneNumber)) { "phone number must be in international form" }
        transport.attachRecoveryNumber(phoneNumber)
        store.setMetaString(META_RECOVERY_NUMBER, phoneNumber)
    }

    fun detachRecoveryNumber() = exclusive {
        transport.detachRecoveryNumber()
        store.setMetaString(META_RECOVERY_NUMBER, "")
    }

    /**
     * A read of how well this device protects the vault, for display.
     *
     * strongBox is true when the wrapping key sits in a discrete secure element
     * rather than the general TEE — a real difference in what an attacker with
     * root can extract, and worth telling the user which they have. environment
     * is the same self-reported signal sent to the gateway, shown so a user on
     * a compromised device is not the last to know.
     */
    data class SecurityPosture(
        /** The live vault key sits in a discrete secure element right now. */
        val strongBox: Boolean,
        /** This device has StrongBox hardware, whether or not the key uses it. */
        val strongBoxHardware: Boolean,
        val environment: String,
    )

    fun securityPosture(): SecurityPosture = SecurityPosture(
        strongBox = DeviceKey.isStrongBoxBacked(),
        strongBoxHardware = appContext.packageManager
            .hasSystemFeature(android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE),
        environment = TamperSignals.describe(TamperSignals.snapshot(appContext)),
    )

    /** The number attached to this account, as this device last left it. */
    val recoveryNumber: String?
        get() = store.getMetaString(META_RECOVERY_NUMBER)?.takeIf { it.isNotBlank() }

    /**
     * Writes the account out to a blob the user can keep somewhere else.
     *
     * Everything is in it — the identity key, the sessions, the pinned keys of
     * every contact and the message history — because a restore that produced
     * a different identity would change the safety number of every
     * conversation, which is the alarm this app rings when someone is being
     * impersonated. A backup that cried wolf on every restore would teach
     * people to ignore it.
     *
     * That completeness is also the danger, and it is the reason this is
     * something a user chooses rather than something that happens: whoever
     * holds the file and its passphrase is the account, and can be that account
     * without any contact noticing.
     */
    fun exportBackup(passphrase: String): ByteArray = exclusive { store.exportBackup(passphrase) }

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
                senderUsername = json.optString("username").takeIf { Handles.isValidUsername(it) },
                sentAt = json.getLong("sentAt"),
                receivedAt = System.currentTimeMillis(),
                groupId = json.optString("groupId").takeIf { Protocol.isValidGroupId(it) },
            ).also { message ->
                // First value wins, and a later message can never change it.
                // This field is attacker-controlled: a peer able to rewrite it
                // could point our replies at any bucket they chose, making every
                // member of that bucket download traffic they never asked for.
                if (store.getMetaLong(peerBucketMeta(message.senderAci)) == null) {
                    store.setMetaLong(peerBucketMeta(message.senderAci), json.getLong("bucketId"))
                }

                val gid = message.groupId
                val control = json.optJSONObject("group")
                if (gid != null && control != null) applyGroupUpdate(gid, control, message.senderAci)
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
        val cursor = store.getMetaLong(META_CURSOR) ?: 0
        if (envelope.seq <= cursor) return

        // Sequence numbers are the gateway's and the client cannot check them.
        // One envelope claiming a very high seq stepped the cursor past every
        // message this account would ever be sent — persisted, so it survived a
        // restart, and silent. Ignored rather than refused: refusing would stall
        // catch-up for good, because the next poll returns the same entry, while
        // skipping it lets every genuine envelope beside it through and leaves
        // the cursor where those put it.
        //
        // The check lives here rather than in the callers so that live socket
        // delivery is covered as well as both catch-up paths.
        if (envelope.seq > cursor + Protocol.MAX_CURSOR_ADVANCE) return

        val message = openEnvelope(envelope)
        store.setMetaLong(META_CURSOR, envelope.seq)
        if (message != null) onMessage(message)
    }

    /** Collects anything that has arrived in the bucket since the last cursor. */
    fun catchUp(onMessage: (IncomingMessage) -> Unit) {
        // Sorted, because the order of this list is the gateway's choice and a
        // hostile one is inside the threat model. consume() steps the cursor to
        // each envelope's seq and skips anything at or below it, so taken in
        // the order they arrived a single envelope carrying a high seq steps
        // the cursor past everything behind it, which is then dropped in
        // silence. A genuine batch returned in reverse lost four messages out
        // of five; one unopenable envelope claiming seq 999999 stepped the
        // cursor beyond every message the account would ever receive.
        val envelopes = transport.since(store.getMetaLong(META_CURSOR) ?: 0).sortedBy { it.seq }
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
                submitWork {
                    runCatching { replenishPreKeys() }
                    runCatching { rotatePreKeys() }
                }
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
                // Sorted for the same reason as in catchUp: the gateway picks
                // this order, and an envelope with a high seq taken early steps
                // the cursor past every one behind it.
                val pending = transport.since(store.getMetaLong(META_CURSOR) ?: 0).sortedBy { it.seq }
                for (envelope in pending) {
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

    /**
     * Replaces the signed and Kyber prekeys once they are old enough.
     *
     * The gateway has always accepted these — the replenish request has fields
     * for both and verifies their signatures — but nothing ever sent them, so
     * a pair generated at registration was served for the life of the account.
     * See Protocol.PREKEY_ROTATION_MS for what that costs.
     *
     * The key being replaced is kept. Someone may have fetched a bundle moments
     * before this ran, and the session they open names the old key; deleting it
     * at once would make that first message undecryptable, and an undecryptable
     * message is dropped in silence here by design. The one before it goes, so
     * exactly two generations are ever held.
     */
    fun rotatePreKeys(now: Long = System.currentTimeMillis()) {
        val rotatedAt = store.getMetaLong(META_PREKEYS_ROTATED_AT) ?: 0L
        if (now - rotatedAt < Protocol.PREKEY_ROTATION_MS) return

        val currentSigned = store.getMetaLong(META_SIGNED_PREKEY_ID)?.toInt() ?: 1
        val currentKyber = store.getMetaLong(META_KYBER_PREKEY_ID)?.toInt() ?: 1
        val nextSigned = currentSigned + 1
        val nextKyber = currentKyber + 1
        if (nextSigned > Protocol.MAX_PREKEY_ID || nextKyber > Protocol.MAX_PREKEY_ID) return

        // Reserved before the keys exist, for the same reason the one-time
        // identifiers are: an upload that lands without the counter following
        // it would have the next rotation overwrite a private key the gateway
        // is still handing the public half of.
        store.setMetaLong(META_SIGNED_PREKEY_ID, nextSigned.toLong())
        store.setMetaLong(META_KYBER_PREKEY_ID, nextKyber.toLong())

        val signed = Keys.generateSignedPreKey(identity, nextSigned, stores)
        val kyber = Keys.generateKyberPreKey(identity, nextKyber, stores)
        transport.replenishKeys(
            JSONObject().apply {
                put("signedPreKey", signed.toJson())
                put("kyberPreKey", kyber.toJson())
            },
        )
        store.setMetaLong(META_PREKEYS_ROTATED_AT, now)

        if (currentSigned > 1) store.deleteRecord("signed_prekeys", (currentSigned - 1).toLong())
        if (currentKyber > 1) store.deleteRecord("kyber_prekeys", (currentKyber - 1).toLong())
    }

    fun replenishPreKeys() {
        val remaining = try {
            transport.remainingOneTimePreKeys()
        } catch (_: TransportError) {
            return
        }
        if (remaining > Protocol.ONE_TIME_PREKEY_LOW_WATER) return

        val firstId = store.getMetaLong(META_NEXT_PREKEY_ID)?.toInt() ?: (Protocol.ONE_TIME_PREKEY_BATCH + 1)
        val count = Protocol.ONE_TIME_PREKEY_BATCH - remaining

        // Reserved before the keys exist, not after they are uploaded.
        //
        // Advancing afterwards leaves a window: if the upload lands and the
        // counter write does not — a crash, a process killed for memory — the
        // next replenishment generates fresh keys under the same identifiers
        // and overwrites the private halves. The gateway then hands out a
        // public prekey whose private key is gone, and the session opened with
        // it fails to decrypt. That failure looks exactly like an envelope
        // meant for another member of the bucket, so it is dropped in silence.
        //
        // Burning identifiers costs nothing: they are 24 bits, and a hundred at
        // a time is a hundred and sixty thousand batches before it matters.
        store.setMetaLong(META_NEXT_PREKEY_ID, (firstId + count).toLong())

        val generated = Keys.generateOneTimePreKeys(firstId, count, stores)
        transport.replenishKeys(JSONObject().apply { put("oneTimePreKeys", generated.toJsonArray()) })
    }

    /* ---- internals ---- */



    companion object {

        private const val META_IDENTITY = "identity"
        private const val META_REGISTRATION_ID = "registrationId"
        private const val META_ACI = "aci"
        private const val META_USERNAME = "username"

        /**
         * The hash of this account's handle, when the handle itself is not known.
         * Written by recovery, which learns the one and not the other.
         */
        private const val META_USERNAME_HASH = "usernameHash"
        private const val META_DEVICE_ID = "deviceId"
        private const val META_BUCKET_ID = "bucketId"
        private const val META_POW_DIFFICULTY = "powDifficulty"
        private const val META_TRUST_ROOT = "trustRoot"
        private const val META_SENDER_CERT = "senderCert"
        private const val META_SENDER_CERT_EXPIRY = "senderCertExpiresAt"
        private const val META_NEXT_PREKEY_ID = "nextPreKeyId"
        private const val META_RECOVERY_NUMBER = "recoveryNumber"
        private const val META_SIGNED_PREKEY_ID = "signedPreKeyId"
        private const val META_KYBER_PREKEY_ID = "kyberPreKeyId"
        private const val META_PREKEYS_ROTATED_AT = "preKeysRotatedAt"
        private const val META_CURSOR = "bucketCursor"

        private fun peerBucketMeta(aci: String): String = "peerBucket:$aci"
        private fun peerAvatarMeta(aci: String): String = "peerAvatar:$aci"
        private const val GROUP_INDEX = "groups:index"
        private fun groupMeta(groupId: String): String = "group:$groupId"
        private fun groupTombstone(groupId: String): String = "groupGone:$groupId"

        private const val SAFETY_NUMBER_ITERATIONS = 5200
        private const val SAFETY_NUMBER_VERSION = 2

        fun register(options: MillygramRegisterOptions): MillygramClient {
            require(Protocol.isValidNickname(options.username)) {
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

            val stores = ProtocolStores.forAccount(store, identity, registrationId)
            val combined = CombinedProtocolStore(stores)

            val signedPreKey = Keys.generateSignedPreKey(identity, 1, stores)
            val kyberPreKey = Keys.generateKyberPreKey(identity, 1, stores)
            val oneTimePreKeys = Keys.generateOneTimePreKeys(1, Protocol.ONE_TIME_PREKEY_BATCH, stores)
            store.setMetaLong(META_NEXT_PREKEY_ID, (Protocol.ONE_TIME_PREKEY_BATCH + 1).toLong())
            store.setMetaLong(META_SIGNED_PREKEY_ID, 1)
            store.setMetaLong(META_KYBER_PREKEY_ID, 1)
            // Generated a moment ago, so the rotation clock starts now rather
            // than at zero — otherwise every new account rotates on its first
            // connection and throws away keys nobody has used.
            store.setMetaLong(META_PREKEYS_ROTATED_AT, System.currentTimeMillis())

            val transport = Transport(
                baseUrl = options.base.serverUrl,
                credentials = null,
                obliviousRelayUrl = options.base.obliviousRelayUrl,
                client = httpFor(options.base),
                environment = environmentSupplier(options.base),
            )

            // Handles the nickname could become, in the order libsignal offered
            // them. The gateway cannot pick one — picking would mean seeing the
            // name in order to hash it — so the client walks its own candidates
            // and takes the next when one is already claimed. Everything about a
            // registration commits to the hash, so a new candidate means a new
            // signature and a new proof of work; there is no cheap retry, and no
            // reason to want one.
            var username: String? = null
            val registered = try {
                var found: Transport.RegisterResponse? = null
                for (candidate in Handles.candidates(options.username)) {
                    val usernameHash = Handles.hash(candidate)
                    val timestamp = System.currentTimeMillis()
                    val signPayload = Protocol.registrationSigningPayload(
                        usernameHash = usernameHash,
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
                        put("usernameHash", Protocol.b64(usernameHash))
                        put("usernameProof", Protocol.b64(Handles.proof(candidate)))
                        put("deviceId", Protocol.DEVICE_ID_PRIMARY)
                        put("registrationId", registrationId)
                        put("identityKey", Protocol.b64(identity.publicKey.serialize()))
                        put("signedPreKey", signedPreKey.toJson())
                        put("kyberPreKey", kyberPreKey.toJson())
                        put("oneTimePreKeys", oneTimePreKeys.toJsonArray())
                        put("timestamp", timestamp)
                        put("signature", Protocol.b64(signature))
                    }

                    // Registration is charged in CPU rather than to an address.
                    // Every user on an Uzbek mobile network shares a handful of
                    // public addresses, so an address-based limit would ration
                    // signups for a whole carrier; work costs the same wherever
                    // it is solved. The retry exists so the gateway can raise the
                    // price during a flood without every installed client
                    // breaking.
                    var difficulty = Protocol.REGISTRATION_POW_DIFFICULTY
                    var attempt = 0
                    var taken = false
                    while (found == null && !taken) {
                        body.put("workNonce", Protocol.solveRegistrationWork(signPayload, difficulty))
                        try {
                            found = transport.register(body)
                        } catch (failure: TransportError) {
                            if (failure.code == "username_taken") {
                                taken = true
                            } else {
                                val harder = failure.code == "work_required" &&
                                    failure.requiredDifficulty != null &&
                                    failure.requiredDifficulty > difficulty
                                if (!harder || attempt > 0) throw failure
                                difficulty = failure.requiredDifficulty
                                attempt += 1
                            }
                        }
                    }

                    if (found != null) {
                        username = candidate
                        break
                    }
                }
                found ?: throw IllegalStateException("every handle offered for that nickname is already taken")
            } catch (t: Throwable) {
                store.close()
                throw t
            }
            val chosenUsername = username ?: error("a registration succeeded without a handle")

            // Checked before a single field of the answer is written, not
            // after. Once the trust root row exists this client believes it,
            // and nothing later in the life of the install asks the question
            // again — so a vault half-populated from an answer we have decided
            // not to trust must not survive this line.
            val trustRoot = try {
                acceptTrustRoot(options.base, registered.trustRoot)
            } catch (t: Throwable) {
                store.close()
                throw t
            }

            // The handle this client chose and proved. The gateway holds only
            // its hash and could not return it, so this is the one copy that
            // exists outside the people who are told it.
            store.setMetaString(META_USERNAME, chosenUsername)
            store.setMetaString(META_ACI, registered.aci)
            if (registered.avatarSeed.isNotEmpty()) {
                store.setMetaString(peerAvatarMeta(registered.aci), registered.avatarSeed)
            }
            store.setMetaString(META_TRUST_ROOT, trustRoot)
            store.setMetaLong(META_BUCKET_ID, registered.bucketId)
            store.setMetaLong(META_POW_DIFFICULTY, registered.powDifficulty.toLong())

            val trustRootKey = ECPublicKey(Protocol.unb64(trustRoot))
            transport.setCredentials(SigningCredentials(registered.aci, Protocol.DEVICE_ID_PRIMARY, identity))

            return MillygramClient(
                store, stores, combined, transport, identity,
                registered.aci, chosenUsername, Protocol.DEVICE_ID_PRIMARY,
                registered.bucketId, registered.powDifficulty, trustRootKey,
                options.base.context.applicationContext,
            )
        }

        /**
         * Asks the gateway to send a recovery code to a number.
         *
         * Takes the whole options object rather than a URL so that this request
         * travels on the same client, with the same pins and the same
         * interception, as every other request the app makes. Recovery used to
         * be the one flow that quietly built its own client, which meant the
         * app's configuration stopped exactly where it mattered most.
         */
        fun startRecovery(options: MillygramOptions, phoneNumber: String) {
            require(Protocol.isValidPhoneNumber(phoneNumber)) { "phone number must be in international form" }
            Transport.Recovery.start(options.serverUrl, phoneNumber, httpFor(options))
        }

        /**
         * The URL-only form, kept so an existing caller still compiles.
         *
         * It cannot honour pins or anything else the app configured, because it
         * is not given them — it has a bare client and a hostname, which is the
         * whole problem. Callers should move to the [MillygramOptions] overload
         * above; this one is here to make that a one-line change rather than a
         * build break.
         */
        @Deprecated("Recovery must run on the client the app configured; pass MillygramOptions instead.")
        fun startRecovery(serverUrl: String, phoneNumber: String) {
            require(Protocol.isValidPhoneNumber(phoneNumber)) { "phone number must be in international form" }
            Transport.Recovery.start(serverUrl, phoneNumber, OkHttpClient.Builder().build())
        }

        /**
         * Rebinds an account to keys generated here, and opens it.
         *
         * What comes back is a handle, not a history. The gateway never held
         * the old private key, so this account is a new identity wearing an old
         * name: the conversations are gone with the device, and every contact
         * will see the safety number change. That last part is not a defect to
         * be smoothed over — it is the only signal a contact gets that the
         * person behind a familiar name is now holding different keys, and
         * whether that is a friend with a new phone or somebody who acquired
         * their SIM is exactly the question they should be asking.
         */
        fun recoverWithCode(
            options: MillygramOptions,
            phoneNumber: String,
            code: String,
        ): MillygramClient {
            require(!options.context.getDatabasePath(options.databaseName).exists()) {
                "this device already holds an account; remove it before recovering"
            }

            val store = LocalStore.open(options.context, options.databaseName, options.passphrase)
            try {
                val identity = IdentityKeyPair.generate()
                val registrationId = Keys.generateRegistrationId()

                store.setMeta(META_IDENTITY, identity.serialize())
                store.setMetaLong(META_REGISTRATION_ID, registrationId.toLong())
                store.setMetaLong(META_DEVICE_ID, Protocol.DEVICE_ID_PRIMARY.toLong())

                val stores = ProtocolStores.forAccount(store, identity, registrationId)
                val signedPreKey = Keys.generateSignedPreKey(identity, 1, stores)
                val kyberPreKey = Keys.generateKyberPreKey(identity, 1, stores)
                val oneTimePreKeys = Keys.generateOneTimePreKeys(1, Protocol.ONE_TIME_PREKEY_BATCH, stores)
                store.setMetaLong(META_NEXT_PREKEY_ID, (Protocol.ONE_TIME_PREKEY_BATCH + 1).toLong())
                store.setMetaLong(META_SIGNED_PREKEY_ID, 1)
                store.setMetaLong(META_KYBER_PREKEY_ID, 1)
                store.setMetaLong(META_PREKEYS_ROTATED_AT, System.currentTimeMillis())

                val timestamp = System.currentTimeMillis()
                val payload = Protocol.recoverySigningPayload(
                    phoneNumber = phoneNumber,
                    code = code,
                    registrationId = registrationId.toLong(),
                    identityKey = identity.publicKey.serialize(),
                    signedPreKeyId = signedPreKey.keyId.toLong(),
                    signedPreKeyPublic = Protocol.unb64(signedPreKey.publicKeyB64),
                    kyberPreKeyId = kyberPreKey.keyId.toLong(),
                    kyberPreKeyPublic = Protocol.unb64(kyberPreKey.publicKeyB64),
                    timestamp = timestamp,
                )

                val body = JSONObject().apply {
                    put("phoneNumber", phoneNumber)
                    put("code", code)
                    put("registrationId", registrationId)
                    put("identityKey", Protocol.b64(identity.publicKey.serialize()))
                    put("signedPreKey", signedPreKey.toJson())
                    put("kyberPreKey", kyberPreKey.toJson())
                    put("oneTimePreKeys", oneTimePreKeys.toJsonArray())
                    put("timestamp", timestamp)
                    put("signature", Protocol.b64(identity.privateKey.calculateSignature(payload)))
                }

                val answer = Transport.Recovery.complete(options.serverUrl, body, httpFor(options))

                // Everything below comes out of an answer to an unauthenticated
                // request made by a device that has nothing pinned yet, so this
                // is the one moment in the life of an install where whoever
                // replies gets to choose what the client will believe
                // afterwards. The username and the bucket are visible to the
                // user and self-correcting; the trust root is neither. It
                // decides which sender certificates are genuine, it is never
                // re-fetched, and a chosen one makes sealed-sender authorship
                // forgeable for as long as the app stays installed — with no
                // symptom the user could notice. So it is checked here against
                // what the build expects, and a mismatch aborts the recovery
                // and takes the half-built vault with it rather than storing a
                // root we cannot account for.
                val trustRoot = acceptTrustRoot(options, answer.getString("trustRoot"))

                val recoveredAci = answer.getString("aci")
                store.setMetaString(META_ACI, recoveredAci)
                answer.optString("avatarSeed", "").takeIf { it.isNotEmpty() }?.let {
                    store.setMetaString(peerAvatarMeta(recoveredAci), it)
                }
                // The gateway holds only the hash and cannot say what the handle
                // was, so recovery hands back the hash and the device confirms a
                // name against it offline. Until somebody does, this account knows
                // its own identity but not its own name.
                store.setMetaString(META_USERNAME_HASH, answer.getString("usernameHash"))
                store.setMetaLong(META_BUCKET_ID, answer.getLong("bucketId"))
                store.setMetaString(META_TRUST_ROOT, trustRoot)
                store.setMetaLong(META_POW_DIFFICULTY, answer.getLong("powDifficulty"))
                store.setMetaString(META_RECOVERY_NUMBER, phoneNumber)
            } catch (t: Throwable) {
                store.close()
                options.context.getDatabasePath(options.databaseName).delete()
                throw t
            }
            store.close()
            return open(options)
        }

        /** Rebuilds a vault from a backup blob. See exportBackup. */
        fun restoreBackup(
            context: android.content.Context,
            databaseName: String,
            backup: ByteArray,
            passphrase: String,
        ) = LocalStore.importBackup(context, databaseName, backup, passphrase)

        /**
         * Opens without a passphrase, using the key the device holds.
         *
         * Null when this device cannot — no vault, no screen lock, or a key the
         * system dropped. The caller asks for the passphrase then, which is
         * also how a restored account gets its device wrapping.
         */
        fun openWithDeviceKey(options: MillygramOptions): MillygramClient? {
            val store = LocalStore.openWithDeviceKey(options.context, options.databaseName)
                ?: return null
            return runCatching { fromStore(store, options) }
                .getOrElse {
                    store.close()
                    null
                }
        }

        /** True when the next launch can skip the passphrase. */
        fun canOpenWithDeviceKey(options: MillygramOptions): Boolean =
            LocalStore.hasDeviceKey(options.context, options.databaseName)

        /**
         * Destroys this device's ability to open the vault without being asked.
         *
         * The account survives — the vault, the identity key, the sessions and
         * the history are all still there, and the passphrase still opens them.
         * What goes is the shortcut: the device wrapping of the data key is
         * nulled out and the keystore entry that could have unwrapped it is
         * deleted, so after this returns [canOpenWithDeviceKey] is false and
         * the only way in is the passphrase.
         *
         * This is what a person reaches for when the phone is about to be out
         * of their hands — a border post, a repair shop, a request to unlock it
         * — where the threat is not somebody copying the database but somebody
         * simply opening the app. Deleting the account would be the wrong
         * answer there: it destroys what they are trying to keep, and an
         * obviously wiped phone is itself an answer to the question being
         * asked. So this leaves an account that looks exactly like an account
         * and asks for a passphrase, which is a thing a messenger is allowed to
         * do.
         *
         * Safe on every path that could be missing: no database, no keystore
         * entry, a vault that never had a device wrapping. Each of those is
         * already the state this call is trying to reach.
         */
        fun forgetDeviceKey(context: android.content.Context, databaseName: String) {
            // Order matters only in that both must happen; each is harmless on
            // its own and neither can be left half-done in a way that leaves the
            // shortcut working. The column is cleared first so that even if the
            // keystore delete were to fail there is no wrapped key left to
            // unwrap.
            LocalStore.clearDeviceKey(context, databaseName)
            DeviceKey.forget()
        }

        fun open(options: MillygramOptions): MillygramClient =
            fromStore(LocalStore.open(options.context, options.databaseName, options.passphrase), options)

        /** Everything after the vault is open, whichever key opened it. */
        private fun fromStore(store: LocalStore, options: MillygramOptions): MillygramClient {
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
                client = httpFor(options),
                environment = environmentSupplier(options),
            )

            return MillygramClient(
                store, stores, combined, transport, identity,
                aci, username, deviceId, bucketId, powDifficulty,
                ECPublicKey(Protocol.unb64(trustRoot)),
                options.context.applicationContext,
            )
        }

        /**
         * The only way any path in this class obtains an HTTP client.
         *
         * Registration, recovery, the authenticated transport and the delivery
         * socket all come through here, so pinning is either on for all of them
         * or off for all of them. The alternative — each call site reaching for
         * whatever client is nearest — is what left recovery running on a client
         * the app had never configured.
         */
        private fun httpFor(options: MillygramOptions): OkHttpClient =
            MillygramHttp.forGateway(
                base = options.http,
                serverUrl = options.serverUrl,
                obliviousRelayUrl = options.obliviousRelayUrl,
                certificatePins = options.certificatePins,
            )

        /**
         * The environment signal, or nothing at all.
         *
         * Null when reporting is off, and the transport then omits the field
         * entirely rather than sending an empty one — the gateway has always
         * treated it as optional, so a request without it is an ordinary
         * request and not a client announcing that it has something to hide.
         * See [MillygramOptions.reportEnvironment] for why off is the default.
         */
        private fun environmentSupplier(options: MillygramOptions): (() -> String)? {
            if (!options.reportEnvironment) return null
            return { TamperSignals.describe(TamperSignals.snapshot(options.context)) }
        }

        /**
         * Checks a trust root the server has just offered against the one this
         * build expects, and returns it if it is allowed to be stored.
         *
         * With no expectation configured this is trust on first answer, which
         * is where the client has always been; the check only exists once a
         * build has been told what to expect. When it has, a mismatch is fatal
         * rather than logged, because a trust root is not a preference to be
         * degraded around — accepting a different one is accepting a different
         * answer to "who really sent this", for the life of the install.
         *
         * The comparison is on the decoded bytes rather than the base64 text so
         * that a difference in padding or whitespace cannot read as a mismatch
         * between two identical keys. It uses MessageDigest.isEqual, which is
         * constant-time, not because there is a secret here — a trust root is a
         * public key and both sides of this comparison are public — but because
         * it costs nothing and spares the next reader from having to work out
         * whether it mattered.
         *
         * An expected value that will not decode fails closed. A build
         * configured with a malformed root is a build whose operator believes
         * the check is running, and quietly turning it off for them would be
         * the worst of the available outcomes.
         */
        private fun acceptTrustRoot(options: MillygramOptions, offered: String): String {
            val expected = options.expectedTrustRoot ?: return offered
            val matches = runCatching {
                MessageDigest.isEqual(Protocol.unb64(expected), Protocol.unb64(offered))
            }.getOrDefault(false)
            check(matches) {
                "the gateway offered a trust root this build does not expect; refusing to pin it"
            }
            return offered
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

