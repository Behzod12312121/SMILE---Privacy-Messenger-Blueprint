import { Fingerprint, PrivateKey } from '@signalapp/libsignal-client';
import { createCipheriv, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import {
  MAX_PLAINTEXT_BYTES,
  OBLIVIOUS_INFO,
  OBLIVIOUS_REQUEST_BYTES,
  PADDED_ENVELOPE_BYTES,
  PADDED_PAYLOAD_BYTES,
  MAX_GROUP_REVISION,
  SIG_AUTH,
  SIG_REGISTER,
  authSigningPayload,
  b64,
  bytes,
  canonical,
  decodeObliviousRequest,
  encodeObliviousRequest,
  pad,
  padPayload,
  recoverySigningPayload,
  registrationSigningPayload,
  solveProofOfWork,
  solveRegistrationWork,
  unpad,
  backupRowsDigest,
  usernameHash,
  usernameProof,
  createUsernameLink,
  USERNAME_LINK_PREFIX,
  USERNAME_LINK_BYTES,
  usernameCandidates,
  NICKNAME_MIN_LENGTH,
  NICKNAME_MAX_LENGTH,
  USERNAME_HASH_BYTES,
  USERNAME_PROOF_BYTES,
  isValidUsername,
  verifyProofOfWork,
  verifyRegistrationWork,
} from '@millygram/protocol';

/**
 * Conformance vectors.
 *
 * MillyGram has two implementations of the same wire protocol: this one, and
 * the Kotlin client. Every value below is produced here and asserted there. A
 * single byte of disagreement in a signing payload or a padding layout is a
 * bug that only shows up as "some messages fail to decrypt", months later,
 * against one platform. These vectors turn that into a failing unit test.
 *
 * The file is generated, never hand-edited. Regenerate with `npm run vectors`.
 */

const hex = (input: Uint8Array): string => Buffer.from(input).toString('hex');
const utf8 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'utf8'));

/** Deterministic filler so a vector is reproducible; real padding uses randomness. */
const patterned = (length: number, seed: number): Uint8Array => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (i * 31 + seed * 17) & 0xff;
  return out;
};

const canonicalCases = [
  { name: 'empty parts', tag: 'millygram/test/v1', parts: [] as (string | number)[] },
  { name: 'single string', tag: 'millygram/test/v1', parts: ['dilnoza_az'] },
  { name: 'string and integer', tag: SIG_AUTH, parts: ['dilnoza_az', 1] },
  { name: 'ambiguity guard a', tag: 'millygram/test/v1', parts: ['ab', 'c'] },
  { name: 'ambiguity guard b', tag: 'millygram/test/v1', parts: ['a', 'bc'] },
  { name: 'large integer', tag: 'millygram/test/v1', parts: [4294967295] },
  { name: 'uzbek text', tag: 'millygram/test/v1', parts: ['Gʻayrat Toʻrayev', 'Aʼzamova'] },
];

const registrationVector = {
  usernameHash: b64(usernameHash('dilnoza_az.42')),
  usernameProof: b64(usernameProof('dilnoza_az.42')),
  deviceId: 1,
  registrationId: 11261,
  identityKey: b64(patterned(33, 1)),
  signedPreKey: { keyId: 1, publicKey: b64(patterned(33, 2)), signature: b64(patterned(64, 3)) },
  kyberPreKey: { keyId: 1, publicKey: b64(patterned(1568, 4)), signature: b64(patterned(64, 5)) },
  oneTimePreKeys: [{ keyId: 1, publicKey: b64(patterned(33, 6)) }],
  timestamp: 1788435744566,
};

// The vault is per-device and never shared, so nothing forces the two
// implementations to store it the same way — which is exactly why they drifted
// without anything noticing. A backup, an export, or a desktop client sharing
// the format would find out the hard way. This vector makes one seal the other
// must be able to open.
const vaultKey = patterned(32, 11);
const vaultPlaintext = patterned(48, 13);
const vaultAad = Buffer.from('millygram/v1/meta/aci', 'utf8');
const vaultNonce = patterned(12, 17);
const vaultCipher = createCipheriv('aes-256-gcm', vaultKey, vaultNonce, { authTagLength: 16 });
vaultCipher.setAAD(vaultAad);
const vaultBody = Buffer.concat([vaultCipher.update(vaultPlaintext), vaultCipher.final()]);
const vaultSealed = Buffer.concat([vaultNonce, vaultBody, vaultCipher.getAuthTag()]);

// The number two people read to each other to check nobody is in the middle.
// Both clients must derive the same digits from the same pair of identities,
// and nothing was checking that they did — a mismatch would have two honest
// people concluding they were under attack.
const fpLocalAci = '11111111-1111-4111-8111-111111111111';
const fpRemoteAci = '22222222-2222-4222-8222-222222222222';
const fpLocalKey = PrivateKey.deserialize(bytes(patterned(32, 19))).getPublicKey();
const fpRemoteKey = PrivateKey.deserialize(bytes(patterned(32, 23))).getPublicKey();
const fingerprint = Fingerprint.new(
  5200,
  2,
  bytes(Buffer.from(fpLocalAci, 'utf8')),
  fpLocalKey,
  bytes(Buffer.from(fpRemoteAci, 'utf8')),
  fpRemoteKey,
)
  .displayableFingerprint()
  .toString();

// Recovery is signed by a key the gateway has never seen, over a payload both
// implementations have to build identically. Getting it wrong would not fail
// loudly — it would refuse every recovery as a bad signature.
const recoveryPayload = recoverySigningPayload({
  phoneNumber: '+998901234567',
  code: '123456',
  registrationId: 4242,
  identityKey: b64(patterned(33, 29)),
  signedPreKey: { keyId: 7, publicKey: b64(patterned(33, 31)), signature: b64(patterned(64, 37)) },
  kyberPreKey: { keyId: 9, publicKey: b64(patterned(1568, 41)), signature: b64(patterned(64, 43)) },
  oneTimePreKeys: [],
  timestamp: 1788000000000,
} as never);

const powContent = patterned(PADDED_ENVELOPE_BYTES, 9);
const powBucket = 7;
const powDifficulty = 12;
const powNonce = solveProofOfWork(powBucket, powContent, powDifficulty);

let powBadNonce = 0;
while (verifyProofOfWork(powBucket, powContent, powBadNonce, powDifficulty)) powBadNonce += 1;

// Registration work is a different domain to submission work, and the two
// implementations have to agree on both the context string and the preimage
// shape. A vector is the only thing that proves they do.
const regPayload = patterned(96, 5);
const regDifficulty = 12;
const regNonce = solveRegistrationWork(regPayload, regDifficulty);
let regBadNonce = 0;
while (verifyRegistrationWork(regPayload, regBadNonce, regDifficulty)) regBadNonce += 1;

const obliviousContent = patterned(PADDED_ENVELOPE_BYTES, 11);
const obliviousEncoded = encodeObliviousRequest(4294967295, 123456, obliviousContent);

const paddedSample = pad(utf8('Ertaga soat 10 da uchrashamizmi?'));
const payloadSample = padPayload('{"v":1,"body":"salom"}');

const vectors = {
  generatedBy: '@millygram/protocol',
  note: 'Generated file. Both implementations must agree on every value here.',
  constants: {
    paddedEnvelopeBytes: PADDED_ENVELOPE_BYTES,
    obliviousRequestBytes: OBLIVIOUS_REQUEST_BYTES,
    maxPlaintextBytes: MAX_PLAINTEXT_BYTES,
    paddedPayloadBytes: PADDED_PAYLOAD_BYTES,
    maxGroupRevision: MAX_GROUP_REVISION,
    sigRegister: SIG_REGISTER,
    sigAuth: SIG_AUTH,
    obliviousInfo: OBLIVIOUS_INFO,
  },
  base64url: [
    { bytesHex: '', encoded: b64(new Uint8Array(0)) },
    { bytesHex: hex(patterned(1, 0)), encoded: b64(patterned(1, 0)) },
    { bytesHex: hex(patterned(2, 0)), encoded: b64(patterned(2, 0)) },
    { bytesHex: hex(patterned(3, 0)), encoded: b64(patterned(3, 0)) },
    { bytesHex: hex(patterned(33, 7)), encoded: b64(patterned(33, 7)) },
    { bytesHex: 'fbff', encoded: b64(new Uint8Array([0xfb, 0xff])) },
  ],
  /**
   * Inputs that must be REJECTED by both implementations.
   *
   * Node's own decoder accepts every one of these and returns something;
   * Java's throws on most. Two implementations that disagree about which byte
   * strings are well-formed is a divergence waiting to bite one platform, so
   * the accepted set is pinned here rather than left to whichever decoder
   * happens to be underneath.
   */
  base64urlRejected: [
    'A', // a trailing group of one character cannot encode anything
    'AAAAA',
    'AAAA=', // padding is not part of the canonical unpadded form
    'AAAA==',
    'AA A', // embedded whitespace
    'AA\nA',
    '+/+/', // the standard alphabet, not the url-safe one
    'AA%3D',
  ],
  canonical: canonicalCases.map((testCase) => ({
    name: testCase.name,
    tag: testCase.tag,
    parts: testCase.parts.map((part) =>
      typeof part === 'number' ? { type: 'int', value: part } : { type: 'string', value: part },
    ),
    expectedHex: hex(canonical(testCase.tag, testCase.parts)),
  })),
  registrationSigningPayload: {
    request: registrationVector,
    expectedHex: hex(registrationSigningPayload(registrationVector)),
  },
  authSigningPayload: {
    aci: '4aecbadd-bec0-4e2f-8f5d-71e0ace76688',
    deviceId: 1,
    nonceHex: hex(patterned(32, 8)),
    expectedHex: hex(authSigningPayload('4aecbadd-bec0-4e2f-8f5d-71e0ace76688', 1, patterned(32, 8))),
  },
  padding: {
    // The filler is random in real use, so the vector pins the framing instead:
    // the length prefix, the payload placement, and the total size.
    payloadHex: hex(utf8('Ertaga soat 10 da uchrashamizmi?')),
    paddedLength: paddedSample.length,
    lengthPrefixHex: hex(paddedSample.subarray(0, 4)),
    payloadAtOffset4Hex: hex(paddedSample.subarray(4, 4 + utf8('Ertaga soat 10 da uchrashamizmi?').length)),
    roundTripHex: hex(unpad(paddedSample)),

    // Payload padding, applied before encryption so the sealed length stops
    // tracking the message. Both sides must produce these bytes exactly: if one
    // pads and the other does not, the two are still interoperable but their
    // envelopes are distinguishable by length, which is the whole defect.
    payloadPaddedLength: payloadSample.length,
    payloadPaddedHeadHex: hex(payloadSample.subarray(0, 24)),
    payloadPaddedTailHex: hex(payloadSample.subarray(payloadSample.length - 8)),
  },

  // The digest that binds a backup's row list. The backup itself is written
  // only on Android; this vector is what makes the two implementations agree
  // about it, because a disagreement here means a restore silently rejects a
  // genuine backup — or worse, accepts a stripped one.
  // The directory slice a name falls in. Both sides must agree exactly: a
  // client that computes a different slice from the gateway simply never finds
  // the person it is looking for.
  // The handle itself. A discriminator the two sides format or parse differently
  // is an account that one implementation can reach and the other cannot.
  // Handles, as libsignal computes them. Both sides call the same Rust code, so
  // these agree by construction rather than by two people reading a spec — but
  // they are pinned anyway, because "the same library" is an assumption that
  // stops being true the moment the two versions drift apart.
  username: {
    nicknameMinLength: NICKNAME_MIN_LENGTH,
    nicknameMaxLength: NICKNAME_MAX_LENGTH,
    hashBytes: USERNAME_HASH_BYTES,
    proofBytes: USERNAME_PROOF_BYTES,
    cases: ['dilnoza.42', 'aziz_test.07', 'a_b_c.1234'].map((username) => ({
      username,
      hashHex: hex(usernameHash(username)),
    })),
    // A proof generated on this side must verify on the other. This is the one
    // that would catch a genuine divergence: the hash is deterministic and easy
    // to agree on, and the proof is where the zero-knowledge machinery lives.
    proof: {
      username: 'dilnoza.42',
      hashHex: hex(usernameHash('dilnoza.42')),
      proofHex: hex(usernameProof('dilnoza.42')),
    },
    // Refused as handles. Dilnoza.42 is refused by this project rather than by
    // libsignal, which allows upper case; two handles that differ only in case
    // would be two accounts nobody could tell apart.
    // A bare nickname matters most: it is what somebody
    // types when they have been told half a name.
    invalid: ['dilnoza', 'dilnoza.', '.42', 'Dilnoza.42', ''],
    // Candidates are random, so only their shape can be pinned.
    candidateCount: usernameCandidates('dilnoza').length,
  },

  // An invite made here must open there. The link carries its own key, so this
  // is the whole of what an introduction depends on — if the two sides disagree
  // about the framing, an invite simply does nothing when it is tapped, which
  // is the kind of failure nobody reports as a bug.
  usernameLink: {
    prefix: USERNAME_LINK_PREFIX,
    packedBytes: USERNAME_LINK_BYTES,
    username: 'dilnoza.42',
    link: createUsernameLink('dilnoza.42'),
  },

  backupRows: {
    rows: [
      { table: 'identities', id: '4bc3e0fd-0000-4000-8000-000000000001', valueHex: hex(utf8('pinned-key-a')) },
      { table: 'sessions', id: '4bc3e0fd-0000-4000-8000-000000000002.1', valueHex: hex(utf8('session-b')) },
      { table: 'meta', id: 'aci', valueHex: hex(utf8('4bc3e0fd-0000-4000-8000-000000000003')) },
    ],
    digestHex: hex(
      backupRowsDigest([
        { table: 'identities', id: '4bc3e0fd-0000-4000-8000-000000000001', value: utf8('pinned-key-a') },
        { table: 'sessions', id: '4bc3e0fd-0000-4000-8000-000000000002.1', value: utf8('session-b') },
        { table: 'meta', id: 'aci', value: utf8('4bc3e0fd-0000-4000-8000-000000000003') },
      ]),
    ),
    // Order is part of the digest, and so is dropping a row.
    reorderedDigestHex: hex(
      backupRowsDigest([
        { table: 'sessions', id: '4bc3e0fd-0000-4000-8000-000000000002.1', value: utf8('session-b') },
        { table: 'identities', id: '4bc3e0fd-0000-4000-8000-000000000001', value: utf8('pinned-key-a') },
        { table: 'meta', id: 'aci', value: utf8('4bc3e0fd-0000-4000-8000-000000000003') },
      ]),
    ),
    withoutIdentitiesDigestHex: hex(
      backupRowsDigest([
        { table: 'sessions', id: '4bc3e0fd-0000-4000-8000-000000000002.1', value: utf8('session-b') },
        { table: 'meta', id: 'aci', value: utf8('4bc3e0fd-0000-4000-8000-000000000003') },
      ]),
    ),
    emptyDigestHex: hex(backupRowsDigest([])),
  },
  proofOfWork: {
    bucketId: powBucket,
    difficulty: powDifficulty,
    contentHex: hex(powContent),
    validNonce: powNonce,
    invalidNonce: powBadNonce,
  },
  safetyNumber: {
    localAci: fpLocalAci,
    remoteAci: fpRemoteAci,
    localIdentityHex: hex(fpLocalKey.serialize()),
    remoteIdentityHex: hex(fpRemoteKey.serialize()),
    digits: fingerprint,
  },
  recoverySigning: {
    phoneNumber: '+998901234567',
    code: '123456',
    registrationId: 4242,
    identityKeyHex: hex(patterned(33, 29)),
    signedPreKeyId: 7,
    signedPreKeyPublicHex: hex(patterned(33, 31)),
    kyberPreKeyId: 9,
    kyberPreKeyPublicHex: hex(patterned(1568, 41)),
    timestamp: 1788000000000,
    payloadSha256Hex: hex(createHash('sha256').update(recoveryPayload).digest()),
  },
  vault: {
    keyHex: hex(vaultKey),
    aad: vaultAad.toString('utf8'),
    plaintextHex: hex(vaultPlaintext),
    sealedHex: hex(vaultSealed),
  },
  registrationWork: {
    difficulty: regDifficulty,
    payloadHex: hex(regPayload),
    validNonce: regNonce,
    invalidNonce: regBadNonce,
  },
  obliviousRequest: {
    bucketId: 4294967295,
    nonce: 123456,
    contentHex: hex(obliviousContent),
    encodedLength: obliviousEncoded.length,
    encodedPrefixHex: hex(obliviousEncoded.subarray(0, 8)),
    decodesBackTo: {
      bucketId: decodeObliviousRequest(obliviousEncoded)?.bucketId,
      nonce: decodeObliviousRequest(obliviousEncoded)?.nonce,
    },
  },
};

const target = resolve(process.argv[2] ?? 'android/protocol/src/test/resources/vectors.json');
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify(vectors, null, 2)}\n`, 'utf8');

/**
 * The gateway's libsignal version, recorded so the Android build can refuse to
 * drift away from it. Both sides ran different versions once — Maven Central
 * lags Signal's own artifact host by a wide margin — and the resulting
 * cross-version questions were only answerable on a device. Pinning both to one
 * version removes the question; this file is what stops it coming back.
 */
const libsignalVersion = createRequire(import.meta.url)(
  '@signalapp/libsignal-client/package.json',
).version as string;

// The client module's tests need the vectors too — the safety number needs
// libsignal's natives, which the protocol module does not depend on. Written
// from here rather than copied, so the two cannot drift.
const clientVectors = resolve('android/client/src/test/resources/vectors.json');
mkdirSync(dirname(clientVectors), { recursive: true });
writeFileSync(clientVectors, `${JSON.stringify(vectors, null, 2)}
`, 'utf8');
console.log(`wrote ${clientVectors}`);

const versionTarget = resolve('android/client/src/test/resources/gateway-libsignal-version.txt');
mkdirSync(dirname(versionTarget), { recursive: true });
writeFileSync(versionTarget, `${libsignalVersion}\n`, 'utf8');

process.stdout.write(`wrote ${target}\n`);
process.stdout.write(`wrote ${versionTarget} (${libsignalVersion})\n`);
process.stdout.write(
  `canonical cases: ${vectors.canonical.length}, base64url cases: ${vectors.base64url.length}\n`,
);
