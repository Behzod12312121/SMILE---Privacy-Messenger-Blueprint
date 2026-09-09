package uz.millygram.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * The MillyGram wire protocol, byte for byte.
 *
 * This is the second implementation of the same protocol; the first is the
 * TypeScript one in `packages/protocol`. Every construction here is pinned by
 * conformance vectors generated from that implementation and asserted in
 * `ProtocolVectorsTest`. A single byte of disagreement in a signing payload or
 * a padding layout would show up in production as "messages from Android
 * sometimes fail", months later — the vectors turn that into a failing test.
 *
 * Byte order is written out explicitly everywhere. Nothing here may depend on
 * the host's native endianness.
 */
object Protocol {

    const val PROTOCOL_VERSION: Int = 1

    /**
     * Domain-separation tags. Every signature commits to exactly one of these,
     * so a signature harvested from one context cannot be replayed into another.
     */
    const val SIG_REGISTER: String = "millygram/register/v1"
    const val SIG_AUTH: String = "millygram/auth/v1"
    const val SIG_RECOVER: String = "millygram/recover/v1"

    /**
     * How many bytes identify a group. Generated on the creating device and
     * registered nowhere: the gateway has no group table and no way to acquire
     * one, because the identifier rides inside the ciphertext where only
     * members can read it.
     */
    const val GROUP_ID_BYTES: Int = 16

    /**
     * The largest group this build will assemble.
     *
     * The gateway cannot fan a message out — it deliberately does not know who
     * is in a group — so the sender uploads one padded 8 KB envelope per
     * member. Fifty is four hundred kilobytes for a single message, already a
     * real cost on mobile data. A product limit, not a protocol one.
     */
    const val MAX_GROUP_MEMBERS: Int = 50

    /**
     * The highest revision a group announcement may carry.
     *
     * Unbounded, the "highest revision wins" rule is a weapon: a member
     * announces 2147483647, and no honest edit can ever exceed it, because the
     * next legitimate value overflows this Int, reads back negative, and is
     * dropped. The group freezes at the attacker's membership and they can
     * never be removed. Must match MAX_GROUP_REVISION in the TypeScript
     * protocol module; a conformance vector pins the pair.
     */
    const val MAX_GROUP_REVISION: Int = 1_000_000
    const val GROUP_NAME_MAX: Int = 64

    /**
     * How many groups a device will accept from other people.
     *
     * Anybody who knows an account identifier can announce a group at it — a
     * documented limitation, and the price of having no server-side membership
     * to consult. Tolerable for a handful of groups; a device-filling attack
     * without a ceiling, because every unseen identifier is another stored
     * entry. Groups already held keep updating after the cap, so reaching it
     * can never cost somebody a group they are really in.
     */
    const val MAX_GROUPS: Int = 256

    /**
     * How far a single envelope may carry the delivery cursor.
     *
     * Sequence numbers are assigned by the gateway and the client has no way to
     * check them. The cursor steps to each envelope's seq and anything at or
     * below it is skipped, so one envelope claiming a very high seq — free for
     * a hostile gateway to invent — moved the cursor beyond every message the
     * account would ever be sent. The cursor is persisted, so a single response
     * silenced an account for good, in silence, across restarts.
     *
     * Envelopes beyond one window are ignored rather than refused, and never
     * move the cursor. Refusing would stall catch-up permanently, because the
     * next poll returns the same entry; ignoring lets the genuine envelopes
     * beside it through. A gateway that stays hostile can still withhold, which
     * it could always do by returning nothing — what this removes is one
     * response causing permanent damage.
     *
     * Must match MAX_CURSOR_ADVANCE in packages/protocol.
     */
    const val MAX_CURSOR_ADVANCE: Long = 100_000L

    /**
     * A group identifier in the only shape this protocol produces: canonical
     * base64url of [GROUP_ID_BYTES].
     *
     * Checked rather than trusted, because the identifier is chosen by whoever
     * sends the announcement and becomes a storage key on the receiving device.
     * Left free-form, one account could send an identifier of any length and
     * have it stored: measured on the TypeScript client at 2,000 characters,
     * a single hostile message grew the victim's vault by thirteen kilobytes.
     */
    fun isValidGroupId(value: String): Boolean =
        CANONICAL_B64URL.matches(value) &&
            value.isNotEmpty() &&
            value.length % 4 != 1 &&
            runCatching { unb64(value).size }.getOrNull() == GROUP_ID_BYTES
    const val POW_CONTEXT: String = "millygram/pow/v1"

    /**
     * A separate context so a submission proof can never be presented as a
     * registration proof, or the reverse. Same hash, different domain.
     */
    const val REGISTRATION_POW_CONTEXT: String = "millygram/pow-register/v1"
    const val OBLIVIOUS_INFO: String = "millygram/oblivious/v1"

    const val DEVICE_ID_PRIMARY: Int = 1
    const val MAX_PLAINTEXT_BYTES: Int = 4096

    /**
     * Leading zero bits a registration must carry.
     *
     * Registration cannot be charged to an identity — there isn't one yet —
     * and charging it to an address punishes everyone behind the same carrier
     * NAT, which in this market is most of a country. So it is charged in CPU.
     * The gateway says so when it wants more, and the client pays that instead.
     *
     * Measured on a Galaxy S23 at 626k hashes/s: 0.42s at eighteen bits, and
     * nearer two seconds on the cheap hardware most of this market carries.
     */
    const val REGISTRATION_POW_DIFFICULTY: Int = 18
    const val PADDED_ENVELOPE_BYTES: Int = 8192

    /**
     * Every sealed payload is padded to exactly this many bytes before encryption.
     *
     * The envelope is a constant 8192 bytes whatever happens, but it states in
     * cleartext how much of itself is real, and the gateway — along with every
     * one of the ~16 accounts sharing the bucket, since all of them download
     * every envelope — reads that number. Measured, it tracked the body to
     * within about ten bytes. Padding the plaintext to a constant removes it.
     *
     * Must match `PADDED_PAYLOAD_BYTES` in the TypeScript protocol module. The
     * headroom below the 8,188 an envelope can hold is deliberate: a
     * session-opening PQXDH message costs ~2,161 bytes on top of the payload,
     * and overshooting is not a bigger envelope but a send that cannot go.
     */
    const val PADDED_PAYLOAD_BYTES: Int = 5888
    const val OBLIVIOUS_REQUEST_BYTES: Int = 8 + PADDED_ENVELOPE_BYTES
    const val ONE_TIME_PREKEY_BATCH: Int = 100
    const val ONE_TIME_PREKEY_LOW_WATER: Int = 20

    /** The largest prekey identifier the wire format carries. */
    const val MAX_PREKEY_ID: Int = 0xffffff

    /**
     * How long a signed or Kyber prekey stays current before a new one replaces
     * it.
     *
     * These are the medium-term half of PQXDH, and medium-term only means
     * anything if they are actually replaced. Left alone they become long-term
     * keys, and the private half on a seized handset then opens the first
     * message of every conversation ever started with that account rather than
     * only those begun since the last rotation. The ratchet protects everything
     * after the first message; this bounds the first.
     */
    const val PREKEY_ROTATION_MS: Long = 48L * 60 * 60 * 1000
    const val DEFAULT_BUCKET_SIZE: Int = 16

    /** JavaScript Number.MAX_SAFE_INTEGER. Both implementations stop here. */
    const val MAX_CANONICAL_INTEGER: Long = 9_007_199_254_740_991L

    private val random = SecureRandom()

    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getUrlDecoder()

    fun b64(bytes: ByteArray): String = encoder.encodeToString(bytes)

    private val CANONICAL_B64URL = Regex("^[A-Za-z0-9_-]*$")

    /**
     * Canonical unpadded base64url, strictly — and identically to the
     * TypeScript side.
     *
     * Java's decoder is already strict where Node's is not, so the guards here
     * mostly exist to make the failure *ours* and the message the same on both
     * platforms. The length check is the one that adds something: it rejects a
     * trailing group of one character, which no valid encoding can produce.
     */
    fun unb64(value: String): ByteArray {
        require(CANONICAL_B64URL.matches(value)) { "not canonical base64url: unexpected character" }
        require(value.length % 4 != 1) { "not canonical base64url: impossible length" }
        val decoded = decoder.decode(value)
        // The alphabet and the length can both be right while the final group
        // still carries bits no encoder would have emitted. "aa" and "aQ" both
        // decode to the single byte 0x69, so without this two different strings
        // are the same value — and anywhere a string is used as a key while the
        // bytes carry the meaning, that is an alias. Re-encoding is the cheapest
        // complete test: exactly one spelling survives it.
        require(b64(decoded) == value) { "not canonical base64url: non-zero trailing bits" }
        return decoded
    }

    /** A part of a canonical payload: either UTF-8 text, an unsigned integer, or raw bytes. */
    sealed interface Part {
        data class Text(val value: String) : Part
        data class Integer(val value: Long) : Part
        data class Raw(val value: ByteArray) : Part {
            override fun equals(other: Any?): Boolean =
                this === other || (other is Raw && value.contentEquals(other.value))

            override fun hashCode(): Int = value.contentHashCode()
        }
    }

    /**
     * Length-prefixed concatenation. Two different field lists can never produce
     * the same bytes, which is what stops a signature over (a, bc) from being
     * reinterpreted as one over (ab, c).
     */
    fun canonical(tag: String, parts: List<Part>): ByteArray {
        val encoded = parts.map { part ->
            when (part) {
                is Part.Text -> part.value.toByteArray(Charsets.UTF_8)
                is Part.Raw -> part.value
                is Part.Integer -> {
                    // Bounded at 2^53-1 to match the TypeScript side, whose
                    // integers stop being exact above that. A value Kotlin would
                    // happily encode and TypeScript could never produce is a
                    // payload only one implementation can sign.
                    require(part.value in 0..MAX_CANONICAL_INTEGER) {
                        "not a canonical integer: ${part.value}"
                    }
                    ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(part.value).array()
                }
            }
        }

        val tagBytes = tag.toByteArray(Charsets.UTF_8)
        val total = tagBytes.size + encoded.sumOf { 4 + it.size }
        val out = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        out.put(tagBytes)
        for (part in encoded) {
            out.putInt(part.size)
            out.put(part)
        }
        return out.array()
    }

    /** Domain tag for the digest that binds a backup's row list. */
    const val BACKUP_ROWS_CONTEXT: String = "millygram/backup-rows/v1"

    /**
     * A digest over a backup's whole row list, in order, and over the bytes each
     * row holds.
     *
     * A backup's wrapped key is authenticated and every row is individually
     * sealed, so nobody without the passphrase can read a row or forge one.
     * Nothing bound the *list*, and removing entries needs neither: the file
     * simply carried fewer, and the restore finished without complaint.
     * Dropping the `identities` rows is the one that matters — those are the
     * pinned contact keys, and a device that restores without them silently
     * accepts the next key it is offered for a contact it had already verified.
     *
     * Sealed under the data key by the caller, so producing a matching digest
     * needs the passphrase. Each row is framed with [canonical] rather than
     * concatenated, so no two different row lists can hash the same.
     */
    fun backupRowsDigest(rows: List<BackupRow>): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (row in rows) {
            digest.update(
                canonical(
                    BACKUP_ROWS_CONTEXT,
                    listOf(Part.Text(row.table), Part.Text(row.id), Part.Raw(row.value)),
                ),
            )
        }
        return digest.digest()
    }

    /** One row of a backup, as the digest above sees it. */
    data class BackupRow(val table: String, val id: String, val value: ByteArray) {
        override fun equals(other: Any?): Boolean =
            this === other ||
                (other is BackupRow && table == other.table && id == other.id && value.contentEquals(other.value))

        override fun hashCode(): Int = (table.hashCode() * 31 + id.hashCode()) * 31 + value.contentHashCode()
    }

    /**
     * Pads a JSON payload out to [PADDED_PAYLOAD_BYTES] with trailing spaces.
     *
     * Spaces rather than a marker byte, because a JSON parser on either side
     * already ignores trailing whitespace — `JSONObject(String)` here and
     * `JSON.parse` in TypeScript both accept it untouched. That is what makes
     * this safe against builds already in the field: a padded payload opens on
     * a client that knows nothing about padding, and an unpadded one from an
     * older build still opens here.
     */
    fun padPayload(json: ByteArray): ByteArray {
        require(json.size <= PADDED_PAYLOAD_BYTES) {
            "payload of ${json.size} bytes exceeds the $PADDED_PAYLOAD_BYTES-byte padded size"
        }
        val out = ByteArray(PADDED_PAYLOAD_BYTES) { ' '.code.toByte() }
        json.copyInto(out)
        return out
    }

    /** Length-prefix, then random filler out to a constant size. */
    fun pad(payload: ByteArray): ByteArray {
        require(payload.size + 4 <= PADDED_ENVELOPE_BYTES) { "payload does not fit the padded envelope" }
        val out = ByteArray(PADDED_ENVELOPE_BYTES)
        random.nextBytes(out)
        ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN).putInt(0, payload.size)
        payload.copyInto(out, 4)
        return out
    }

    fun unpad(padded: ByteArray): ByteArray {
        require(padded.size == PADDED_ENVELOPE_BYTES) { "padded payload has the wrong size" }
        val length = ByteBuffer.wrap(padded).order(ByteOrder.BIG_ENDIAN).getInt(0)
        require(length >= 0 && length + 4 <= PADDED_ENVELOPE_BYTES) {
            "padded payload declares an impossible length"
        }
        return padded.copyOfRange(4, 4 + length)
    }

    private fun sha256(vararg chunks: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (chunk in chunks) digest.update(chunk)
        return digest.digest()
    }

    private fun leadingZeroBits(digest: ByteArray): Int {
        var count = 0
        for (byte in digest) {
            val value = byte.toInt() and 0xff
            if (value == 0) {
                count += 8
                continue
            }
            return count + Integer.numberOfLeadingZeros(value) - 24
        }
        return count
    }

    /**
     * Explicitly big-endian. A native-order view would produce a different
     * protocol on a host with the opposite byte order.
     */
    private fun registrationPreimage(payload: ByteArray): ByteArray =
        REGISTRATION_POW_CONTEXT.toByteArray(Charsets.UTF_8) + sha256(payload)

    /** Solves the work a registration has to carry. */
    fun solveRegistrationWork(payload: ByteArray, difficulty: Int): Long =
        solveWork(registrationPreimage(payload), difficulty)

    fun verifyRegistrationWork(payload: ByteArray, nonce: Long, difficulty: Int): Boolean =
        verifyWork(registrationPreimage(payload), nonce, difficulty)

    /**
     * The search loop for both kinds of work.
     *
     * One MessageDigest for the whole run, reused. Asking the provider for a
     * fresh instance per attempt costs more than the hash does, and at a
     * million attempts that was the difference between a second and half a
     * minute on a handset — paid on every signup and, through the submission
     * proof, on every message sent.
     */
    private fun solveWork(preimage: ByteArray, difficulty: Int): Long {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(preimage.size + 4)
        preimage.copyInto(buffer)
        // Written into rather than returned, so the search allocates nothing.
        val out = ByteArray(32)

        var nonce = 0L
        while (nonce <= 0xffffffffL) {
            writeUInt32BE(buffer, preimage.size, nonce)
            digest.update(buffer)
            digest.digest(out, 0, out.size)
            if (leadingZeroBits(out) >= difficulty) return nonce
            nonce += 1
        }
        throw IllegalStateException("no proof of work found")
    }

    private fun verifyWork(preimage: ByteArray, nonce: Long, difficulty: Int): Boolean {
        val buffer = ByteArray(preimage.size + 4)
        preimage.copyInto(buffer)
        writeUInt32BE(buffer, preimage.size, nonce)
        return leadingZeroBits(sha256(buffer)) >= difficulty
    }

    private fun powPreimage(bucketId: Long, content: ByteArray): ByteArray {
        val bucket = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(bucketId.toInt()).array()
        return POW_CONTEXT.toByteArray(Charsets.UTF_8) + bucket + sha256(content)
    }

    /**
     * Submission is anonymous, so the relay cannot charge a sender for flooding
     * a bucket. It charges CPU instead: cheap once, expensive a million times,
     * and it reveals nothing about who paid.
     */
    fun solveProofOfWork(bucketId: Long, content: ByteArray, difficulty: Int): Long =
        solveWork(powPreimage(bucketId, content), difficulty)

    fun verifyProofOfWork(bucketId: Long, content: ByteArray, nonce: Long, difficulty: Int): Boolean =
        verifyWork(powPreimage(bucketId, content), nonce, difficulty)


    private fun writeUInt32BE(target: ByteArray, offset: Int, value: Long) {
        target[offset] = ((value ushr 24) and 0xff).toByte()
        target[offset + 1] = ((value ushr 16) and 0xff).toByte()
        target[offset + 2] = ((value ushr 8) and 0xff).toByte()
        target[offset + 3] = (value and 0xff).toByte()
    }

    private fun readUInt32BE(source: ByteArray, offset: Int): Long =
        ((source[offset].toLong() and 0xff) shl 24) or
            ((source[offset + 1].toLong() and 0xff) shl 16) or
            ((source[offset + 2].toLong() and 0xff) shl 8) or
            (source[offset + 3].toLong() and 0xff)

    data class ObliviousRequest(val bucketId: Long, val nonce: Long, val content: ByteArray) {
        override fun equals(other: Any?): Boolean =
            this === other ||
                (other is ObliviousRequest &&
                    bucketId == other.bucketId &&
                    nonce == other.nonce &&
                    content.contentEquals(other.content))

        override fun hashCode(): Int =
            (31 * bucketId.hashCode() + nonce.hashCode()) * 31 + content.contentHashCode()
    }

    /**
     * A fixed byte layout rather than an encoded HTTP message, because the send
     * path has exactly one shape. Fixed offsets cannot be mis-parsed.
     */
    fun encodeObliviousRequest(bucketId: Long, nonce: Long, content: ByteArray): ByteArray {
        require(isUint32(bucketId) && isUint32(nonce)) { "bucket id and nonce must be uint32" }
        require(content.size == PADDED_ENVELOPE_BYTES) { "envelope must be padded before sealing" }

        val out = ByteArray(OBLIVIOUS_REQUEST_BYTES)
        writeUInt32BE(out, 0, bucketId)
        writeUInt32BE(out, 4, nonce)
        content.copyInto(out, 8)
        return out
    }

    fun decodeObliviousRequest(plain: ByteArray): ObliviousRequest? {
        if (plain.size != OBLIVIOUS_REQUEST_BYTES) return null
        return ObliviousRequest(
            bucketId = readUInt32BE(plain, 0),
            nonce = readUInt32BE(plain, 4),
            content = plain.copyOfRange(8, plain.size),
        )
    }

    private fun isUint32(value: Long): Boolean = value in 0..0xffffffffL

    /** Mirrors the field order of the TypeScript implementation exactly. */
    fun registrationSigningPayload(
        usernameHash: ByteArray,
        deviceId: Long,
        registrationId: Long,
        identityKey: ByteArray,
        signedPreKeyId: Long,
        signedPreKeyPublic: ByteArray,
        kyberPreKeyId: Long,
        kyberPreKeyPublic: ByteArray,
        timestamp: Long,
    ): ByteArray = canonical(
        SIG_REGISTER,
        listOf(
            Part.Raw(usernameHash),
            Part.Integer(deviceId),
            Part.Integer(registrationId),
            Part.Raw(identityKey),
            Part.Integer(signedPreKeyId),
            Part.Raw(signedPreKeyPublic),
            Part.Integer(kyberPreKeyId),
            Part.Raw(kyberPreKeyPublic),
            Part.Integer(timestamp),
        ),
    )

    /** Mirrors the field order of the TypeScript implementation exactly. */
    fun recoverySigningPayload(
        phoneNumber: String,
        code: String,
        registrationId: Long,
        identityKey: ByteArray,
        signedPreKeyId: Long,
        signedPreKeyPublic: ByteArray,
        kyberPreKeyId: Long,
        kyberPreKeyPublic: ByteArray,
        timestamp: Long,
    ): ByteArray = canonical(
        SIG_RECOVER,
        listOf(
            Part.Text(phoneNumber),
            Part.Text(code),
            Part.Integer(registrationId),
            Part.Raw(identityKey),
            Part.Integer(signedPreKeyId),
            Part.Raw(signedPreKeyPublic),
            Part.Integer(kyberPreKeyId),
            Part.Raw(kyberPreKeyPublic),
            Part.Integer(timestamp),
        ),
    )

    fun authSigningPayload(aci: String, deviceId: Long, nonce: ByteArray): ByteArray =
        canonical(SIG_AUTH, listOf(Part.Text(aci), Part.Integer(deviceId), Part.Raw(nonce)))

    /** Kept beside the pattern, so a caller trimming input cannot disagree with it. */
    const val NICKNAME_MAX_LENGTH: Int = 32

    /**
     * ASCII only, deliberately. Allowing Unicode would let an attacker register
     * a handle that renders identically to someone else's.
     */
    private val NICKNAME = Regex("^[a-z0-9_]{3,32}$")

    /**
     * True for the part a person chooses, before any handle exists.
     *
     * Whole handles are libsignal's business — it owns the format, computes the
     * hash and builds the proof — and live in the client module beside it. What
     * stays here is the rule this project adds on top: the nickname is ASCII, so
     * that no handle can be made to render identically to another.
     */
    fun isValidNickname(value: String): Boolean = NICKNAME.matches(value)

    private val PHONE = Regex("""^\+[1-9][0-9]{7,14}$""")

    /** International form, which is the only shape the gateway will take. */
    fun isValidPhoneNumber(value: String): Boolean = PHONE.matches(value)

    /**
     * Trims typed input down to what [isValidNickname] will accept.
     *
     * Lives next to the pattern deliberately. The onboarding field used to do
     * this itself with isLetterOrDigit, which is Unicode-aware and therefore
     * accepted Cyrillic — a script most of this market can type without
     * trying. The field took the name and the protocol refused it a tap later,
     * complaining about a-z. Worse in principle: Cyrillic а and Latin a render
     * identically, so a rule that admitted both would let one person be
     * mistaken for another, which is the reason the pattern is ASCII in the
     * first place.
     *
     * Too short to be valid is left to [isValidNickname]; a filter that
     * silently lengthened input would be a strange thing.
     */
    fun sanitizeNickname(input: String): String =
        input.lowercase()
            .filter { it in 'a'..'z' || it in '0'..'9' || it == '_' }
            .take(NICKNAME_MAX_LENGTH)
}
