package uz.millygram.client

import org.signal.libsignal.usernames.BaseUsernameException
import org.signal.libsignal.usernames.Username
import uz.millygram.protocol.Protocol

/**
 * Handles, and why the gateway is never told one.
 *
 * A handle is a nickname, a dot, and digits — `dilnoza.42`. What travels and
 * what is stored is never that string: it is a 32-byte hash of it, together
 * with a proof that whoever sent the hash knows a handle producing it.
 *
 * The hash is what makes the directory unenumerable in the way that matters. A
 * gateway holding plaintext handles holds a list somebody can be made to hand
 * over; a gateway holding hashes holds something an adversary has to attack
 * name by name, and the discriminator means each name costs many guesses rather
 * than one.
 *
 * The proof is what stops the obvious abuse of the first idea. If a hash alone
 * were enough to claim a name, anybody could claim any hash — including hashes
 * they cannot compute a preimage for — and sit on names they cannot use. The
 * proof is a zero-knowledge statement that the sender knows the handle behind
 * the hash, and it reveals nothing else about it.
 *
 * None of this is written here. It is libsignal's `usernames` module, the same
 * Rust implementation Signal ships for its own usernames and the same one the
 * TypeScript side calls, so the two agree by construction rather than by two
 * people reading one specification. That matters more than usual for a scheme
 * like this: the hash is a Ristretto point derived from the parts of the name,
 * and a second hand-written implementation is exactly the kind of thing that
 * agrees on every test vector and diverges on the one name nobody tried.
 *
 * It lives in this module rather than beside [uz.millygram.protocol.Protocol]
 * because that module is deliberately pure JVM with no libsignal in it, and the
 * nickname rule that does live there needs nothing else.
 */
object Handles {

    /** Bounds libsignal is asked to work within. Must match packages/protocol. */
    const val NICKNAME_MIN_LENGTH: Int = 3
    const val NICKNAME_MAX_LENGTH: Int = 32

    /** Sizes libsignal produces, pinned so a wire check can refuse early. */
    const val USERNAME_HASH_BYTES: Int = 32
    const val USERNAME_PROOF_BYTES: Int = 128

    /**
     * Whole handles a nickname could become, with the digits already chosen.
     *
     * The discriminator comes from here rather than from the person
     * registering: somebody choosing their own picks 01, or a birth year, and
     * the values it exists to spread names across collapse to the few that get
     * guessed first. The gateway cannot draw it either — it would have to see
     * the name to hash it — so the client draws, and takes the next candidate
     * when one is already claimed.
     */
    fun candidates(nickname: String): List<String> =
        Username.candidatesFrom(nickname, NICKNAME_MIN_LENGTH, NICKNAME_MAX_LENGTH)
            .map { it.username }

    /** The 32 bytes a handle is stored and looked up by. Throws on a malformed handle. */
    fun hash(username: String): ByteArray = Username(username).hash

    /** A proof that the caller knows the handle behind the hash it is presenting. */
    fun proof(username: String): ByteArray = Username(username).generateProof()

    /**
     * Whether a proof really is for that hash.
     *
     * libsignal signals failure by throwing, which is right for a library and
     * wrong for anything deciding whether to accept a request: a refusal is a
     * boolean, not an exception escaping into a caller that was not expecting
     * one.
     */
    fun verifyProof(proof: ByteArray, hash: ByteArray): Boolean = runCatching {
        Username.verifyProof(proof, hash)
    }.isSuccess

    /**
     * Whether a string is a handle at all, with libsignal as the authority.
     *
     * Deliberately not a regular expression for the format itself. The rules
     * about leading zeros and single digits are libsignal's to enforce, and a
     * second copy of them here is a copy that drifts — silently, because the two
     * would only disagree about names nobody happened to try.
     *
     * The one rule added on top is this project's and not libsignal's: the
     * nickname must be lower-case ASCII. libsignal accepts `Dilnoza.42`, which
     * hashes differently from `dilnoza.42` and is therefore a different account
     * wearing a name most people could not tell apart from it. That is the same
     * confusion the ASCII-only rule exists to prevent, so it is applied to whole
     * handles as well as to the nicknames people type.
     */
    fun isValidUsername(value: String): Boolean =
        runCatching { Username(value) }.isSuccess && Protocol.isValidNickname(nicknameOf(value))

    /** The nickname half of a handle, for showing a name without its digits. */
    fun nicknameOf(username: String): String =
        username.substringBeforeLast('.', missingDelimiterValue = username)

    /**
     * The prefix that marks a MillyGram invite, so a pasted one can be
     * recognised without guessing. Must match USERNAME_LINK_PREFIX in
     * packages/protocol.
     */
    const val LINK_PREFIX: String = "mg1:"

    /** 32 bytes of key and 112 of ciphertext, both fixed by libsignal. */
    const val LINK_ENTROPY_BYTES: Int = 32
    const val LINK_BYTES: Int = 144

    /**
     * An invite: a handle somebody can be given in one tap.
     *
     * Handles carry digits nobody can guess and there is no directory to browse,
     * which is the point — and it means the only way to be found is for somebody
     * to be told your name. This is that, made transferable.
     *
     * The whole thing travels in the token. The alternative, and what Signal
     * does, is to keep the ciphertext on the server under a random handle so the
     * link can later be revoked; that would mean the gateway seeing a request
     * every time somebody opened an invite, which is a record of who is being
     * introduced to whom — the exact thing the rest of this work removed. So the
     * gateway is not in this path at all, and the cost is stated rather than
     * hidden: an invite cannot be withdrawn once it is out.
     *
     * The name is encrypted rather than written into the token. Anybody holding
     * the invite can read it — that is what an invite is for — but it does not
     * sit in a chat log or a link preview as a searchable string, and the
     * ciphertext is a constant 112 bytes whatever the handle, so its length
     * gives nothing away either.
     */
    fun createLink(username: String): String {
        val link = Username(username).generateLink()
        val packed = ByteArray(LINK_BYTES)
        link.entropy.copyInto(packed, 0)
        link.encryptedUsername.copyInto(packed, LINK_ENTROPY_BYTES)
        return LINK_PREFIX + Protocol.b64(packed)
    }

    /**
     * The handle inside an invite, or null when there is not one.
     *
     * Null rather than a throw for every way this can fail — a truncated paste,
     * a token from something else, a tampered one — because all of them arrive
     * the same way, through somebody pasting into a field, and none of them are
     * exceptional enough to be an exception.
     */
    fun usernameFromLink(link: String): String? {
        val trimmed = link.trim()
        if (!trimmed.startsWith(LINK_PREFIX)) return null

        val packed = runCatching { Protocol.unb64(trimmed.removePrefix(LINK_PREFIX)) }.getOrNull()
            ?: return null
        if (packed.size != LINK_BYTES) return null

        val username = runCatching {
            Username.fromLink(
                Username.UsernameLink(
                    packed.copyOfRange(0, LINK_ENTROPY_BYTES),
                    packed.copyOfRange(LINK_ENTROPY_BYTES, LINK_BYTES),
                ),
            ).username
        }.getOrNull() ?: return null

        // libsignal will decrypt anything its own key opens, including a handle
        // this project would refuse to register. An invite is not a way around
        // the rule that names are lower-case ASCII.
        return username.takeIf { isValidUsername(it) }
    }
}
