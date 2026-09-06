import { createHash, randomFillSync } from 'node:crypto';
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
 * Every envelope is padded to exactly this size, after encryption rather than
 * before. Padding the plaintext is not enough: the ciphertext also grows and
 * shrinks with ratchet state, so envelopes stayed distinguishable by length
 * even when the payload inside them did not. Padding the finished envelope
 * makes every one of them byte-identical in size.
 */
export const PADDED_ENVELOPE_BYTES = 8192;

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
  return bytes(Buffer.from(value, 'base64url'));
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

  for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
    buffer.writeUInt32BE(nonce, preimage.length);
    if (leadingZeroBits(createHash('sha256').update(buffer).digest()) >= difficulty) return nonce;
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
 * ASCII only, deliberately. Allowing Unicode here would let an attacker
 * register a handle that renders identically to someone else's; a homoglyph
 * attack on identity is far more dangerous than Latin-only handles are
 * inconvenient.
 */
const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
export const isValidUsername = (value: string): boolean => USERNAME_RE.test(value);

const b64url = (label: string, maxBytes: number) =>
  z
    .string()
    .max(Math.ceil(maxBytes / 3) * 4 + 4)
    .refine((v) => /^[A-Za-z0-9_-]+$/.test(v), label + ' must be base64url')
    .refine((v) => {
      const len = unb64(v).length;
      return len > 0 && len <= maxBytes;
    }, label + ' has an invalid length');

export const Username = z.string().regex(USERNAME_RE, 'username must be 3-32 chars of [a-z0-9_]');
export const Aci = z.uuid();
export const DeviceId = z.number().int().min(1).max(127);
export const KeyId = z.number().int().min(1).max(0xffffff);
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
  username: Username,
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
    req.username,
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
