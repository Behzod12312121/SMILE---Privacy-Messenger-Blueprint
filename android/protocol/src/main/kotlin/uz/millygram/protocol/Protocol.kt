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
        return decoder.decode(value)
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
        username: String,
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
            Part.Text(username),
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

    fun authSigningPayload(aci: String, deviceId: Long, nonce: ByteArray): ByteArray =
        canonical(SIG_AUTH, listOf(Part.Text(aci), Part.Integer(deviceId), Part.Raw(nonce)))

    /** Kept beside the pattern, so a caller trimming input cannot disagree with it. */
    const val USERNAME_MAX_LENGTH: Int = 32

    private val USERNAME = Regex("^[a-z0-9_]{3,32}$")

    /**
     * ASCII only, deliberately. Allowing Unicode would let an attacker register
     * a handle that renders identically to someone else's.
     */
    fun isValidUsername(value: String): Boolean = USERNAME.matches(value)

    /**
     * Trims typed input down to what [isValidUsername] will accept.
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
     * Too short to be valid is left to [isValidUsername]; a filter that
     * silently lengthened input would be a strange thing.
     */
    fun sanitizeUsername(input: String): String =
        input.lowercase()
            .filter { it in 'a'..'z' || it in '0'..'9' || it == '_' }
            .take(USERNAME_MAX_LENGTH)
}
