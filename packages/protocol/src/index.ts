import { createHash, randomFillSync, hash } from 'node:crypto';
import { usernames } from '@signalapp/libsignal-client';
import { z } from 'zod';

export const PROTOCOL_VERSION = 1;

/**
 * Domain-separation tags. Every signature this protocol produces commits to
 * exactly one of these, so a signature harvested from one context can never be
 * replayed into another.
 */
export const SIG_REGISTER = 'millygram/register/v1';
export const SIG_AUTH = 'millygram/auth/v1';
export const POW_CONTEXT = 'millygram/pow/v1';

/**
 * A separate context so a submission proof can never be presented as a
 * registration proof, or the reverse. Same hash, different domain.
 */
export const REGISTRATION_POW_CONTEXT = 'millygram/pow-register/v1';

export const DEVICE_ID_PRIMARY = 1;

/** How long a delivery certificate stays usable before the client must refresh. */
export const SENDER_CERT_TTL_MS = 24 * 60 * 60 * 1000;
/** How long an auth challenge stays open. Short, because clients answer instantly. */
export const AUTH_CHALLENGE_TTL_MS = 60 * 1000;
/** Undelivered envelopes are dropped after this. Nothing is archived. */
export const ENVELOPE_TTL_MS = 14 * 24 * 60 * 60 * 1000;

export const MAX_PLAINTEXT_BYTES = 4096;
export const MAX_ENVELOPE_BYTES = 16 * 1024;
export const ONE_TIME_PREKEY_BATCH = 100;
export const ONE_TIME_PREKEY_LOW_WATER = 20;

/**
 * How long a signed or Kyber prekey stays current before a new one replaces it.
 *
 * These are the medium-term half of PQXDH, and medium-term only means anything
 * if they are actually replaced. Left alone they become long-term keys, and the
 * private half sitting on a seized handset then opens the first message of
 * every conversation ever started with that account, rather than only those
 * begun since the last rotation. The ratchet protects everything after the
 * first message; this bounds the first.
 *
 * Two days, matching what Signal does, and the previous key is kept for one
 * further interval so bundles already handed out still open.
 */
export const PREKEY_ROTATION_MS = 48 * 60 * 60 * 1000;

/**
 * Every envelope is padded to exactly this size, after encryption rather than
 * before. Padding the plaintext is not enough: the ciphertext also grows and
 * shrinks with ratchet state, so envelopes stayed distinguishable by length
 * even when the payload inside them did not. Padding the finished envelope
 * makes every one of them byte-identical in size.
 */
export const PADDED_ENVELOPE_BYTES = 8192;

/**
 * Every sealed payload is padded to exactly this many bytes *before* encryption.
 *
 * Padding the finished envelope was never enough on its own. The envelope is
 * 8192 bytes whatever happens, but it carries a cleartext length prefix, and
 * the gateway — and every one of the ~16 accounts sharing the bucket, since all
 * of them download every envelope — reads it. Measured, that prefix tracked the
 * body to within about ten bytes:
 *
 *     body 1 -> 2224    body 1000 -> 3233    body 4000 -> 6225
 *
 * which is enough to separate a six-digit code from a one-word reply from a
 * paragraph, to pair a request with its answer by length, and to recognise the
 * same body fanned out to a group. Padding the plaintext to a constant removes
 * all of it: the sealed length no longer depends on what was written.
 *
 * The value is bounded by what libsignal adds on top. A session-opening PQXDH
 * message costs the most — 2,146 to 2,158 bytes measured across payload sizes,
 * against 453 to 465 once the session is established — and the padded envelope
 * has 8,188 bytes to give. 5,888 leaves 142 bytes of headroom above the worst
 * overhead seen, because overshooting here is not a bigger envelope (the
 * envelope is a fixed 8192 either way, and the slack is random filler) but a
 * send that fails outright.
 *
 * What this does not hide is the one bit distinguishing a session-opening
 * message from an established one: those two differ by ~1,700 bytes of PQXDH
 * material, and equalising them would mean padding by an amount that depends on
 * ratchet state the sender cannot read without risking an envelope that no
 * longer fits. That bit is documented rather than hidden.
 */
export const PADDED_PAYLOAD_BYTES = 5888;

/**
 * Pads a JSON payload out to [PADDED_PAYLOAD_BYTES] with trailing spaces.
 *
 * Spaces rather than a length field or a marker byte, because a JSON parser on
 * either side already ignores trailing whitespace — `JSON.parse` in TypeScript
 * and `JSONObject(String)` in Kotlin both accept it untouched. That is what
 * makes this change safe to deploy against clients already in the field: a
 * padded payload opens correctly on a build that knows nothing about padding,
 * and an unpadded one from an older build still opens here.
 */
export function padPayload(json: string): Bytes {
  const raw = Buffer.from(json, 'utf8');
  if (raw.length > PADDED_PAYLOAD_BYTES) {
    throw new RangeError(`payload of ${raw.length} bytes exceeds the ${PADDED_PAYLOAD_BYTES}-byte padded size`);
  }
  const out = Buffer.alloc(PADDED_PAYLOAD_BYTES, 0x20);
  raw.copy(out);
  return bytes(out);
}

/**
 * How many accounts share a delivery bucket. Envelopes are addressed to the
 * bucket rather than the account, so the relay learns that one of this many
 * people received something and cannot narrow it further.
 */
export const DEFAULT_BUCKET_SIZE = 16;

/**
 * Leading zero bits a registration must carry.
 *
 * Registration cannot be charged to an identity — there isn't one yet — and
 * charging it to an address punishes everyone behind the same carrier NAT,
 * which in this market is most of a country. So it is charged in CPU, the same
 * trade the submission path already makes. Twenty bits is a few seconds on a
 * cheap handset and is paid once per account, where submission's sixteen is
 * paid per message.
 *
 * This is what a client solves before asking. The server decides what it will
 * accept and says so when they differ, so it can be raised under load without
 * every client needing a new build.
 */
export const REGISTRATION_POW_DIFFICULTY = 18;

/**
 * libsignal's bindings require `Uint8Array<ArrayBuffer>` specifically, and a
 * Node Buffer is typed as `Uint8Array<ArrayBufferLike>`. Copying into a fresh
 * ArrayBuffer here means the distinction is handled once, at the boundary,
 * instead of being cast away at every call site.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

export function bytes(input: Uint8Array): Bytes {
  const out = new Uint8Array(new ArrayBuffer(input.byteLength));
  out.set(input);
  return out;
}

export function b64(input: Uint8Array): string {
  return Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString('base64url');
}

/**
 * Canonical unpadded base64url, strictly.
 *
 * Node's own decoder is extremely forgiving: it silently accepts embedded
 * whitespace, the standard `+/` alphabet, stray `=` padding, and lengths that
 * cannot be valid — never throwing, just returning whatever it could make of
 * the input. Java's URL decoder rejects every one of those.
 *
 * Two implementations of one protocol that disagree about which byte strings
 * are even well-formed is the worst kind of bug: it is invisible until it hits
 * one platform in production. Both sides now accept exactly the canonical form
 * and nothing else.
 */
const CANONICAL_B64URL = /^[A-Za-z0-9_-]*$/;

export function unb64(value: string): Bytes {
  if (!CANONICAL_B64URL.test(value)) {
    throw new RangeError('not canonical base64url: unexpected character');
  }
  // A group of four encodes three bytes; a trailing group of one is impossible.
  if (value.length % 4 === 1) {
    throw new RangeError('not canonical base64url: impossible length');
  }
  const decoded = Buffer.from(value, 'base64url');
  // The alphabet and the length can both be right while the final group still
  // carries bits no encoder would have emitted. "aa" and "aQ" both decode to
  // the single byte 0x69, so without this two different strings are the same
  // value — and anywhere a string is used as a key while the bytes are what
  // carry the meaning, that is an alias. Re-encoding is the cheapest complete
  // test: exactly one spelling survives it.
  if (decoded.toString('base64url') !== value) {
    throw new RangeError('not canonical base64url: non-zero trailing bits');
  }
  return bytes(decoded);
}

/**
 * Length-prefixed concatenation. Two different field lists can never produce
 * the same bytes, which is what stops a signature over (a, bc) from being
 * reinterpreted as one over (ab, c).
 */
export function canonical(tag: string, parts: readonly (Uint8Array | string | number)[]): Bytes {
  const encoded: Uint8Array[] = parts.map((part) => {
    if (typeof part === 'string') return Buffer.from(part, 'utf8');
    if (typeof part === 'number') {
      if (!Number.isSafeInteger(part) || part < 0) throw new RangeError('not a canonical integer: ' + part);
      const buf = Buffer.alloc(8);
      buf.writeBigUInt64BE(BigInt(part));
      return buf;
    }
    return part;
  });

  const tagBytes = Buffer.from(tag, 'utf8');
  const total = tagBytes.length + encoded.reduce((sum, part) => sum + 4 + part.length, 0);
  const out = new Uint8Array(new ArrayBuffer(total));
  out.set(tagBytes, 0);

  let offset = tagBytes.length;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (const part of encoded) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Domain tag for the digest that binds a backup's row list. */
export const BACKUP_ROWS_CONTEXT = 'millygram/backup-rows/v1';

/**
 * A digest over a backup's whole row list, in order, and over the bytes each
 * row holds.
 *
 * A backup's wrapped key is authenticated and every row is individually sealed,
 * so nobody without the passphrase can read a row or forge one. Nothing bound
 * the *list*, though, and removing entries needs neither: the file simply
 * carried fewer, and the restore finished without complaint. Dropping the
 * `identities` rows is the one that matters — those are the pinned contact
 * keys, and a device that restores without them silently accepts the next key
 * it is offered for a contact it had already verified. Pinning removed, no
 * warning.
 *
 * Sealed under the data key by the caller, so producing a matching digest needs
 * the passphrase. Each row is framed with `canonical` rather than concatenated,
 * so no two different row lists can hash the same.
 *
 * This lives here, in the protocol module, because the backup is written and
 * read only on Android — which means this function is the one part of it that
 * conformance vectors can pin across both implementations. The TypeScript side
 * has no backup of its own; it exists to be the oracle.
 */
export function backupRowsDigest(
  rows: readonly { table: string; id: string; value: Uint8Array }[],
): Bytes {
  const digest = createHash('sha256');
  for (const row of rows) {
    digest.update(canonical(BACKUP_ROWS_CONTEXT, [row.table, row.id, row.value]));
  }
  return bytes(digest.digest());
}

/** Length-prefix, then random filler out to a constant size. */
export function pad(payload: Uint8Array): Bytes {
  if (payload.length + 4 > PADDED_ENVELOPE_BYTES) throw new RangeError('payload does not fit the padded envelope');
  const out = new Uint8Array(new ArrayBuffer(PADDED_ENVELOPE_BYTES));
  randomFillSync(out);
  new DataView(out.buffer).setUint32(0, payload.length, false);
  out.set(payload, 4);
  return out;
}

export function unpad(padded: Uint8Array): Bytes {
  if (padded.length !== PADDED_ENVELOPE_BYTES) throw new Error('padded payload has the wrong size');
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (length + 4 > PADDED_ENVELOPE_BYTES) throw new Error('padded payload declares an impossible length');
  return bytes(padded.subarray(4, 4 + length));
}

/**
 * Oblivious submission. The client seals a request to the gateway's public key
 * and hands it to a relay run by a different operator: the relay sees the
 * client's address but only ciphertext, and the gateway sees the request but
 * never the address. Neither half alone can link a sender to a bucket.
 *
 * The request is a fixed byte layout rather than an encoded HTTP message,
 * because the send path has exactly one shape. Fixed offsets cannot be
 * mis-parsed.
 */
/**
 * The exact size of a sealed oblivious request: the fixed request layout plus
 * HPKE's ephemeral key and tag.
 *
 * Fixed on purpose. The gateway cannot see the proof of work inside one of
 * these until it has decrypted it, so decryption is the first thing an
 * unauthenticated caller can make it do, and it is not cheap. Knowing the
 * exact length lets anything that is not a candidate be dropped before any key
 * agreement happens. A test pins this against what sealing actually produces,
 * so a change in libsignal's overhead fails the build rather than quietly
 * rejecting every submission in the field.
 */
export const OBLIVIOUS_SEALED_BYTES = 8249;

export const OBLIVIOUS_INFO = 'millygram/oblivious/v1';
export const OBLIVIOUS_REQUEST_BYTES = 8 + PADDED_ENVELOPE_BYTES;

const isUint32 = (value: number): boolean => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;

export function encodeObliviousRequest(bucketId: number, nonce: number, content: Uint8Array): Bytes {
  if (!isUint32(bucketId) || !isUint32(nonce)) throw new RangeError('bucket id and nonce must be uint32');
  if (content.length !== PADDED_ENVELOPE_BYTES) throw new RangeError('envelope must be padded before sealing');

  const out = new Uint8Array(new ArrayBuffer(OBLIVIOUS_REQUEST_BYTES));
  const view = new DataView(out.buffer);
  view.setUint32(0, bucketId, false);
  view.setUint32(4, nonce, false);
  out.set(content, 8);
  return out;
}

export function decodeObliviousRequest(
  plain: Uint8Array,
): { bucketId: number; nonce: number; content: Bytes } | null {
  if (plain.length !== OBLIVIOUS_REQUEST_BYTES) return null;
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  return {
    bucketId: view.getUint32(0, false),
    nonce: view.getUint32(4, false),
    content: bytes(plain.subarray(8)),
  };
}

const leadingZeroBits = (digest: Uint8Array): number => {
  let count = 0;
  for (const byte of digest) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    return count + Math.clz32(byte) - 24;
  }
  return count;
};

const registrationPreimage = (payload: Uint8Array): Buffer =>
  Buffer.concat([
    Buffer.from(REGISTRATION_POW_CONTEXT, 'utf8'),
    createHash('sha256').update(payload).digest(),
  ]);

/** Solves the work a registration has to carry. See REGISTRATION_POW_DIFFICULTY. */
export function solveRegistrationWork(payload: Uint8Array, difficulty: number): number {
  const preimage = registrationPreimage(payload);
  const buffer = Buffer.alloc(preimage.length + 4);
  preimage.copy(buffer, 0);

  for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
    buffer.writeUInt32BE(nonce, preimage.length);
    if (leadingZeroBits(createHash('sha256').update(buffer).digest()) >= difficulty) return nonce;
  }
  throw new Error('no registration proof of work found');
}

export function verifyRegistrationWork(
  payload: Uint8Array,
  nonce: number,
  difficulty: number,
): boolean {
  const preimage = registrationPreimage(payload);
  const buffer = Buffer.alloc(preimage.length + 4);
  preimage.copy(buffer, 0);
  buffer.writeUInt32BE(nonce, preimage.length);
  return leadingZeroBits(createHash('sha256').update(buffer).digest()) >= difficulty;
}

const powPreimage = (bucketId: number, content: Uint8Array): Buffer => {
  // Explicitly big-endian. A typed-array view would use the host's byte order,
  // which happens to be little-endian everywhere this runs today and would
  // silently produce a different protocol on a machine where it is not.
  const bucket = Buffer.alloc(4);
  bucket.writeUInt32BE(bucketId);
  return Buffer.concat([
    Buffer.from(POW_CONTEXT, 'utf8'),
    bucket,
    createHash('sha256').update(content).digest(),
  ]);
};

/**
 * Submission is anonymous, so the relay cannot charge a sender for flooding a
 * bucket. It charges CPU instead: cheap once, expensive a million times, and it
 * reveals nothing about who paid.
 */
export function solveProofOfWork(bucketId: number, content: Uint8Array, difficulty: number): number {
  const preimage = powPreimage(bucketId, content);
  const buffer = Buffer.alloc(preimage.length + 4);
  preimage.copy(buffer, 0);

  // crypto.hash rather than createHash().update().digest(): the one-shot form
  // skips allocating a hash object per attempt and is measurably faster on the
  // same hardware.
  //
  // Speed here is a fairness question, not an optimisation. The work is a price
  // the honest sender pays, and an attacker writing their own solver will use
  // the fastest primitive available. If the reference client uses a slower one,
  // the honest user pays more per message than the attacker does — exactly
  // backwards. Measured at roughly 1.5x on this machine.
  const digest = (input: Buffer): Buffer =>
    typeof hash === 'function'
      ? (hash('sha256', input, 'buffer') as Buffer)
      : createHash('sha256').update(input).digest();

  for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
    buffer.writeUInt32BE(nonce, preimage.length);
    if (leadingZeroBits(digest(buffer)) >= difficulty) return nonce;
  }
  throw new Error('no proof of work found');
}

export function verifyProofOfWork(
  bucketId: number,
  content: Uint8Array,
  nonce: number,
  difficulty: number,
): boolean {
  const preimage = powPreimage(bucketId, content);
  const buffer = Buffer.alloc(preimage.length + 4);
  preimage.copy(buffer, 0);
  buffer.writeUInt32BE(nonce, preimage.length);
  return leadingZeroBits(createHash('sha256').update(buffer).digest()) >= difficulty;
}

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
 * name by name, and the discriminator means each name costs ten thousand
 * guesses rather than one. The earlier version of this file hashed handles with
 * scrypt to make each of those guesses expensive as well, which is a genuinely
 * better answer to an offline attack — and it was attached to a gateway that
 * still stored the plaintext beside it, so it protected nothing that was not
 * already lying in the clear one column over. Storing only the hash is worth
 * more than making a hash nobody stores expensive.
 *
 * The proof is what stops the obvious abuse of the first idea. If a hash were
 * enough to claim a name, anybody could claim any hash — including hashes they
 * cannot compute a preimage for — and sit on names they cannot use. The proof
 * is a zero-knowledge statement that the sender knows the handle behind the
 * hash, and it reveals nothing else.
 *
 * None of this is written here. It is libsignal's `usernames` module, the same
 * Rust implementation Signal ships for its own usernames and the same one on
 * both sides of this project, so the two agree by construction rather than by
 * two people reading the same specification. That matters more than usual for
 * a scheme like this: the hash is a Ristretto point derived from the parts of
 * the name, and a hand-written second implementation is exactly the kind of
 * thing that agrees on every test vector and diverges on the one name nobody
 * tried.
 */
export const NICKNAME_MIN_LENGTH = 3;
export const NICKNAME_MAX_LENGTH = 32;

/** Sizes libsignal produces, pinned so a wire validator can reject early. */
export const USERNAME_HASH_BYTES = 32;
export const USERNAME_PROOF_BYTES = 128;

/**
 * ASCII only, deliberately. Allowing Unicode here would let an attacker
 * register a handle that renders identically to someone else's; a homoglyph
 * attack on identity is far more dangerous than Latin-only handles are
 * inconvenient.
 *
 * This checks the nickname a person types, before any handle exists. libsignal
 * is the authority on whether a whole handle is well formed, and it is stricter
 * than this in ways that are its business rather than ours.
 */
const NICKNAME_RE = /^[a-z0-9_]{3,32}$/;
export const isValidNickname = (value: string): boolean => NICKNAME_RE.test(value);

/**
 * Whole handles a nickname could become, with the digits already chosen.
 *
 * The discriminator comes from here rather than from the person registering,
 * for the same reason it used to be drawn by the gateway: somebody choosing
 * their own picks 01, or a birth year, and the ten thousand values it exists to
 * spread names across collapse to the few that get guessed first. The gateway
 * cannot draw it any more — it would have to see the name to hash it — so the
 * client draws it, and takes the next candidate when one is already claimed.
 */
export function usernameCandidates(nickname: string): string[] {
  return usernames.generateCandidates(nickname, NICKNAME_MIN_LENGTH, NICKNAME_MAX_LENGTH);
}

/**
 * Whether a string is a handle at all, with libsignal as the authority.
 *
 * Deliberately not a regular expression. The format has rules about leading
 * zeros and single digits that are libsignal's to enforce, and a second copy of
 * them here is a copy that drifts — and drifts silently, because the two only
 * disagree about names nobody happened to try.
 */
export function isValidUsername(value: string): boolean {
  try {
    usernames.hash(value);
  } catch {
    return false;
  }
  // libsignal accepts `Dilnoza.42`, which hashes differently from `dilnoza.42`
  // and is therefore a different account wearing a name most people could not
  // tell apart from it. Same confusion the ASCII rule exists to prevent.
  return isValidNickname(value.slice(0, value.lastIndexOf('.')));
}

/** The 32 bytes a handle is stored and looked up by. Throws on a malformed handle. */
export function usernameHash(username: string): Bytes {
  return bytes(usernames.hash(username));
}

/** A proof that the caller knows the handle behind the hash it is presenting. */
export function usernameProof(username: string): Bytes {
  return bytes(usernames.generateProof(username));
}

/**
 * Whether a proof really is for that hash.
 *
 * libsignal signals failure by throwing, which is right for a library and wrong
 * for a route handler: an exception escaping here is a 500 with an internal
 * message attached, reachable unauthenticated by anybody willing to send 128
 * bytes of nonsense. A refusal is a boolean.
 */
export function verifyUsernameProof(proof: Uint8Array, hash: Uint8Array): boolean {
  try {
    usernames.verifyProof(bytes(proof), bytes(hash));
    return true;
  } catch {
    return false;
  }
}

/**
 * The prefix that marks a MillyGram invite, so a pasted one can be recognised
 * without guessing.
 *
 * Not an https link, because there is no domain to hang one on and inventing
 * one would mean a web server in the path of an introduction — somewhere a
 * request lands, and therefore somewhere a record could be kept of who opened
 * whose invite. A token people paste into whatever they are already using keeps
 * that out of the design entirely.
 */
export const USERNAME_LINK_PREFIX = 'mg1:';

/** 32 bytes of key and 112 of ciphertext, both fixed by libsignal. */
export const USERNAME_LINK_ENTROPY_BYTES = 32;
export const USERNAME_LINK_BYTES = 144;

/**
 * An invite: a handle somebody can be given in one tap.
 *
 * Handles now carry digits nobody can guess and there is no directory to browse,
 * which is the point — and it means the only way to be found is for somebody to
 * be told your name. This is that, made transferable.
 *
 * The whole thing travels in the token. The alternative, and what Signal does,
 * is to keep the ciphertext on the server under a random handle so the link can
 * later be revoked; that would mean the gateway seeing a request every time
 * somebody opened an invite, which is a record of who is being introduced to
 * whom — the exact thing the rest of this work went to some trouble to remove.
 * So the gateway is not in this path at all, and the cost is stated plainly
 * rather than hidden: an invite cannot be withdrawn once it is out.
 *
 * The name is encrypted rather than simply written into the token. Anybody
 * holding the invite can read it — that is what an invite is for — but it does
 * not sit in a chat log, a link preview or a URL bar as a searchable string,
 * and the ciphertext is a constant 112 bytes whatever the handle, so its length
 * gives nothing away either.
 */
export function createUsernameLink(username: string): string {
  const link = usernames.createUsernameLink(username);
  const packed = new Uint8Array(USERNAME_LINK_BYTES);
  packed.set(link.entropy, 0);
  packed.set(link.encryptedUsername, USERNAME_LINK_ENTROPY_BYTES);
  return USERNAME_LINK_PREFIX + b64(packed);
}

/**
 * The handle inside an invite, or null when there is not one.
 *
 * Null rather than a throw for every way this can fail — a truncated paste, a
 * token from something else entirely, a tampered one — because all of them
 * arrive the same way, through somebody pasting into a field, and none of them
 * are exceptional enough to be an exception.
 */
export function usernameFromLink(link: string): string | null {
  const trimmed = link.trim();
  if (!trimmed.startsWith(USERNAME_LINK_PREFIX)) return null;

  let packed: Uint8Array;
  try {
    packed = unb64(trimmed.slice(USERNAME_LINK_PREFIX.length));
  } catch {
    return null;
  }
  if (packed.length !== USERNAME_LINK_BYTES) return null;

  try {
    const username = usernames.decryptUsernameLink({
      entropy: bytes(packed.subarray(0, USERNAME_LINK_ENTROPY_BYTES)),
      encryptedUsername: bytes(packed.subarray(USERNAME_LINK_ENTROPY_BYTES)),
    });
    // libsignal will decrypt anything its own key opens, including a handle
    // this project would refuse to register. An invite is not a way around the
    // rule that names are lower-case ASCII.
    return isValidUsername(username) ? username : null;
  } catch {
    return null;
  }
}

const b64url = (label: string, maxBytes: number) =>
  z
    .string()
    .max(Math.ceil(maxBytes / 3) * 4 + 4)
    .refine((v) => /^[A-Za-z0-9_-]+$/.test(v), label + ' must be base64url')
    .refine((v) => {
      // unb64 reports non-canonical input by throwing, which is right for a
      // decoder and wrong inside a validator. A thrown error is not a
      // validation failure: it escapes safeParse entirely and surfaces as a
      // 500 with the internal message attached. Every route taking one of
      // these fields — registration, submission, auth — could be made to
      // return one, unauthenticated, with four characters of nonsense.
      let length: number;
      try {
        length = unb64(v).length;
      } catch {
        return false;
      }
      return length > 0 && length <= maxBytes;
    }, label + ' has an invalid length');

/**
 * A plaintext handle.
 *
 * This never travels to the gateway. It exists for the one place a name is sent
 * in the clear — a sender's claim about itself, sealed inside an envelope only
 * the recipient can open — and the recipient checks that claim against the
 * directory rather than believing it.
 */
export const Username = z
  .string()
  .max(NICKNAME_MAX_LENGTH + 12)
  .refine(isValidUsername, 'not a well-formed handle');

/** The 32 bytes a handle is known by. The gateway never sees more of a name than this. */
export const UsernameHash = b64url('username hash', USERNAME_HASH_BYTES);

/** The zero-knowledge proof that the sender knows the handle behind that hash. */
export const UsernameProof = b64url('username proof', USERNAME_PROOF_BYTES);

/**
 * A number in E.164, which is the only form the gateway ever sees or stores a
 * hash of. Uzbek mobile numbers are +998 followed by nine digits; the pattern
 * is deliberately general because a diaspora exists and lives on other codes.
 */
export const PhoneNumber = z
  .string()
  .regex(/^\+[1-9][0-9]{7,14}$/, 'phone number must be in international form, like +998901234567');

/** Digits of a recovery code. Short because it is typed from an SMS, and rate limited hard. */
export const RECOVERY_CODE_DIGITS = 6;

/** How long a recovery code stays usable. Short: it is delivered in seconds. */
export const RECOVERY_CODE_TTL_MS = 10 * 60 * 1000;
export const Aci = z.uuid();
export const DeviceId = z.number().int().min(1).max(127);
/** The largest prekey identifier the wire format carries. */
export const MAX_PREKEY_ID = 0xffffff;
export const KeyId = z.number().int().min(1).max(MAX_PREKEY_ID);
export const RegistrationId = z.number().int().min(1).max(0x3fff);
export const BucketId = z.number().int().min(0).max(0xffffffff);

export const SignedPreKeySchema = z.object({
  keyId: KeyId,
  publicKey: b64url('signed prekey', 64),
  signature: b64url('signed prekey signature', 128),
});

export const KyberPreKeySchema = z.object({
  keyId: KeyId,
  publicKey: b64url('kyber prekey', 2048),
  signature: b64url('kyber prekey signature', 128),
});

export const OneTimePreKeySchema = z.object({
  keyId: KeyId,
  publicKey: b64url('one-time prekey', 64),
});

export const RegisterRequest = z.object({
  // The name, in the only form that travels: its hash, and a proof that the
  // sender knows what hashes to it. Without the proof a hash would be a name
  // anybody could claim without being able to use it.
  usernameHash: UsernameHash,
  usernameProof: UsernameProof,
  deviceId: DeviceId,
  registrationId: RegistrationId,
  identityKey: b64url('identity key', 64),
  signedPreKey: SignedPreKeySchema,
  kyberPreKey: KyberPreKeySchema,
  oneTimePreKeys: z.array(OneTimePreKeySchema).min(1).max(ONE_TIME_PREKEY_BATCH),
  timestamp: z.number().int().positive(),
  signature: b64url('registration signature', 128),
  /**
   * Proof of work over the signing payload. Not covered by the signature: it
   * proves effort, not authorship, and the signature already proves the latter.
   */
  workNonce: z.number().int().min(0).max(0xffffffff),
});
export type RegisterRequest = z.infer<typeof RegisterRequest>;

export const RegisterResponse = z.object({
  aci: Aci,
  // No name comes back. The client chose the handle, hashed it and proved it,
  // so it already knows what it is called — and the gateway could not return it
  // even if the client wanted it to.
  bucketId: BucketId,
  trustRoot: b64url('trust root', 64),
  powDifficulty: z.number().int().min(0).max(32),
});
export type RegisterResponse = z.infer<typeof RegisterResponse>;

export const ChallengeResponse = z.object({
  nonce: b64url('nonce', 32),
  expiresAt: z.number().int().positive(),
});
export type ChallengeResponse = z.infer<typeof ChallengeResponse>;

export const AuthRequest = z.object({
  aci: Aci,
  deviceId: DeviceId,
  nonce: b64url('nonce', 32),
  signature: b64url('auth signature', 128),
  /**
   * A self-reported read of how compromised the device looks — "clean",
   * "root,hook", and so on. Deliberately outside the signed payload and
   * deliberately untrusted: a rooted client can report whatever it likes, so
   * signing it would lend it an authority it does not have. The gateway treats
   * it as a hint to risk-score a session, never as proof of anything.
   */
  environment: z.string().max(64).optional(),
});
export type AuthRequest = z.infer<typeof AuthRequest>;

export const AuthResponse = z.object({
  token: z.string().min(1).max(512),
  expiresAt: z.number().int().positive(),
});
export type AuthResponse = z.infer<typeof AuthResponse>;

export const PreKeyBundleResponse = z.object({
  aci: Aci,
  deviceId: DeviceId,
  bucketId: BucketId,
  registrationId: RegistrationId,
  identityKey: b64url('identity key', 64),
  signedPreKey: SignedPreKeySchema,
  kyberPreKey: KyberPreKeySchema,
  oneTimePreKey: OneTimePreKeySchema.nullable(),
});
export type PreKeyBundleResponse = z.infer<typeof PreKeyBundleResponse>;

export const DirectoryResponse = z.object({
  aci: Aci,
  deviceId: DeviceId,
  bucketId: BucketId,
});
export type DirectoryResponse = z.infer<typeof DirectoryResponse>;

export const DeliveryCertificateResponse = z.object({
  certificate: b64url('sender certificate', 4096),
  expiresAt: z.number().int().positive(),
});
export type DeliveryCertificateResponse = z.infer<typeof DeliveryCertificateResponse>;

/**
 * What the relay actually stores. It names neither the sender nor the
 * recipient: the sender is inside `content` under sealed sender, and the
 * recipient is only ever a bucket shared by many accounts. Every envelope is
 * the same size. There is no field here the operator could turn into a record
 * of who talked to whom.
 */
/**
 * Attaching a number to an account, so it can be recovered on a new handset.
 *
 * Deliberately not part of registration. Signing up asks for nothing, and this
 * is a thing somebody chooses afterwards knowing what it costs: a gateway that
 * can answer "which account has this number" is a gateway holding a link
 * between an account and a passport, because that is what SIM registration
 * means in this country.
 */
/**
 * Attaches a number to the calling account. No code, by design.
 *
 * Nothing proves the caller owns the number, and the number is only checked
 * when it is used: a code goes to it at recovery time and recovery is what the
 * code buys. Typing the wrong number is therefore unrecoverable — the account
 * is now attached to a phone its owner does not hold — which is a real cost,
 * accepted because a verification step at signup is the friction this whole
 * feature exists to avoid.
 */
/**
 * How many bytes an avatar is drawn from.
 *
 * Assigned by the gateway at registration and served alongside an account's
 * keys. It is not a preference and there is no route that sets it: the account
 * holder cannot choose how they appear to other people, which is what stops an
 * avatar from being a channel one user can push chosen bytes down to another.
 * Eight bytes is far more than the art needs and small enough to ride along in
 * a bundle nobody notices.
 */
/**
 * How many bytes identify a group.
 *
 * Generated on the device that creates the group and never registered
 * anywhere. The gateway has no group table and no way to acquire one: a group
 * message is an ordinary envelope to an ordinary bucket, and the identifier
 * that ties those envelopes together rides inside the ciphertext where only
 * members can read it. Sixteen bytes so two groups cannot collide by accident
 * and cannot be guessed by anyone wanting to inject into one.
 */
export const GROUP_ID_BYTES = 16;

/**
 * A group identifier in the only shape this protocol ever produces: base64url
 * of GROUP_ID_BYTES.
 *
 * Validated rather than taken as an opaque string, because the identifier is
 * attacker-chosen and becomes a storage key on the recipient's device. Left
 * free-form, one account could send a groupId of any length it liked and have
 * the recipient store it: measured at 2,000 characters, a single hostile
 * message grew the victim's vault by thirteen kilobytes, and nothing bounded
 * how many times it could be repeated. Constraining the field to the shape a
 * real group actually has removes the length half of that entirely.
 */
export const GroupId = b64url('group id', GROUP_ID_BYTES).refine(
  (v) => {
    try {
      return unb64(v).length === GROUP_ID_BYTES;
    } catch {
      return false;
    }
  },
  `a group id is exactly ${GROUP_ID_BYTES} bytes`,
);

/**
 * How many groups a device will accept from other people.
 *
 * Anybody who knows an account identifier can add it to a group — a documented
 * limitation, and the cost of having no server-side membership to consult. That
 * is tolerable for a handful of groups and is a device-filling attack without a
 * ceiling, since each announcement of an unseen identifier creates another
 * entry. The cap bounds it. Existing groups keep updating after it is reached;
 * only unseen ones are refused, so hitting the ceiling can never cost somebody
 * a group they are actually in.
 */
export const MAX_GROUPS = 256;

/**
 * How far a single catch-up may move the delivery cursor.
 *
 * Sequence numbers are assigned by the gateway and the client has no way to
 * check them. The cursor moves to each envelope's seq as it is handled and
 * anything at or below it is skipped, so one envelope claiming a very high seq
 * — which costs a hostile gateway nothing to invent — moved the cursor beyond
 * every message that account would ever be sent. The cursor is persisted, so
 * one response silenced an account permanently, in silence, and it survived a
 * restart.
 *
 * Envelopes beyond this distance are ignored rather than refused, and the
 * cursor is never moved past it. That distinction matters: refusing the batch
 * outright would stall catch-up for good, because the next poll returns the
 * same poisoned batch. Ignoring the outlier lets every genuine envelope in the
 * same batch through and leaves the cursor where those envelopes put it, so
 * delivery continues and a client that really is a long way behind still
 * advances — one window per poll.
 *
 * A gateway that stays hostile can still withhold messages, which it could
 * always do by returning nothing. What this removes is the case where a single
 * response, from an attacker who then goes away, causes permanent damage.
 */
export const MAX_CURSOR_ADVANCE = 100_000;

/**
 * The largest group this build will assemble.
 *
 * Not an arbitrary round number. The gateway cannot fan a message out, because
 * it deliberately does not know who is in a group, so the sender uploads one
 * padded 8 KB envelope per member. Fifty members is four hundred kilobytes for
 * one message, which is already a real cost on the mobile data this app is
 * meant for. Raising it trades that bandwidth away; it is a product decision
 * rather than a protocol limit.
 */
export const MAX_GROUP_MEMBERS = 50;

/**
 * The highest revision a group announcement may carry.
 *
 * Revisions order concurrent edits: the highest one seen wins, and anything at
 * or below the stored value is ignored as stale. Left unbounded, that ordering
 * is a weapon. A member announces revision 2147483647; every client stores it;
 * and no honest edit can ever exceed it, because the next legitimate value is
 * 2147483648 — which does not fit a 32-bit signed integer, is read back
 * negative on Android, and is dropped as malformed. The group is frozen at
 * whatever membership the attacker announced, permanently, and the member who
 * did it can never be removed. That is the opposite of what removal is for.
 *
 * A million edits is past any real group's lifetime — one a day for 2,700
 * years — while leaving three orders of magnitude of headroom below the 32-bit
 * ceiling, so no arithmetic on either side can reach a value the other cannot
 * represent. Both implementations must agree on it, which is why it is pinned
 * by a conformance vector rather than written down twice.
 */
export const MAX_GROUP_REVISION = 1_000_000;

export const GROUP_NAME_MAX = 64;

export const AVATAR_SEED_BYTES = 8;

export const AttachNumberRequest = z.object({
  phoneNumber: PhoneNumber,
});
export type AttachNumberRequest = z.infer<typeof AttachNumberRequest>;

export const StartRecoveryRequest = z.object({
  phoneNumber: PhoneNumber,
});
export type StartRecoveryRequest = z.infer<typeof StartRecoveryRequest>;

/**
 * Finishing a recovery replaces the account's identity key with a new one.
 *
 * The gateway never had the old private key and cannot give it back, so this
 * returns a handle and not a history: the conversations were only ever on the
 * lost device. Every contact sees the safety number change, which is correct —
 * the person they are now talking to is holding different keys, and whether
 * that is their friend on a new phone or somebody who obtained their SIM is
 * exactly the question the safety number exists to ask.
 */
export const CompleteRecoveryRequest = z.object({
  phoneNumber: PhoneNumber,
  code: z.string().regex(/^[0-9]{6}$/, 'recovery code must be six digits'),
  identityKey: b64url('identity key', 64),
  registrationId: RegistrationId,
  signedPreKey: SignedPreKeySchema,
  kyberPreKey: KyberPreKeySchema,
  oneTimePreKeys: z.array(OneTimePreKeySchema).min(1).max(ONE_TIME_PREKEY_BATCH),
  timestamp: z.number().int().positive(),
  signature: b64url('recovery signature', 128),
});
export type CompleteRecoveryRequest = z.infer<typeof CompleteRecoveryRequest>;

export const SIG_RECOVER = 'millygram/recover/v1';

/** What the new identity signs to prove it is the one asking. */
export function recoverySigningPayload(
  req: Omit<CompleteRecoveryRequest, 'signature'>,
): Bytes {
  return canonical(SIG_RECOVER, [
    req.phoneNumber,
    req.code,
    req.registrationId,
    unb64(req.identityKey),
    req.signedPreKey.keyId,
    unb64(req.signedPreKey.publicKey),
    req.kyberPreKey.keyId,
    unb64(req.kyberPreKey.publicKey),
    req.timestamp,
  ]);
}

export const Envelope = z.object({
  bucketId: BucketId,
  content: b64url('envelope content', MAX_ENVELOPE_BYTES),
  nonce: z.number().int().min(0).max(0xffffffff),
});
export type Envelope = z.infer<typeof Envelope>;

export const StoredEnvelope = z.object({
  seq: z.number().int().positive(),
  content: b64url('envelope content', MAX_ENVELOPE_BYTES),
  arrivedAt: z.number().int().positive(),
});
export type StoredEnvelope = z.infer<typeof StoredEnvelope>;

export const ReplenishRequest = z.object({
  signedPreKey: SignedPreKeySchema.optional(),
  kyberPreKey: KyberPreKeySchema.optional(),
  oneTimePreKeys: z.array(OneTimePreKeySchema).max(ONE_TIME_PREKEY_BATCH).optional(),
});
export type ReplenishRequest = z.infer<typeof ReplenishRequest>;

/**
 * The socket only ever says "your bucket has something new". Envelopes are not
 * acknowledged: an acknowledgement would tell the relay which member of a
 * bucket a given envelope was for, which is exactly what buckets exist to hide.
 * Envelopes expire on a timer instead, and clients track their own cursor.
 */
export const ServerToClient = z.discriminatedUnion('type', [
  z.object({ type: z.literal('envelope'), envelope: StoredEnvelope }),
  z.object({ type: z.literal('caught-up') }),
]);
export type ServerToClient = z.infer<typeof ServerToClient>;

export function registrationSigningPayload(
  req: Omit<RegisterRequest, 'signature' | 'workNonce'>,
): Bytes {
  return canonical(SIG_REGISTER, [
    unb64(req.usernameHash),
    req.deviceId,
    req.registrationId,
    unb64(req.identityKey),
    req.signedPreKey.keyId,
    unb64(req.signedPreKey.publicKey),
    req.kyberPreKey.keyId,
    unb64(req.kyberPreKey.publicKey),
    req.timestamp,
  ]);
}

export function authSigningPayload(aci: string, deviceId: number, nonce: Uint8Array): Bytes {
  return canonical(SIG_AUTH, [aci, deviceId, nonce]);
}
