import { mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import {
  MAX_PLAINTEXT_BYTES,
  OBLIVIOUS_INFO,
  OBLIVIOUS_REQUEST_BYTES,
  PADDED_ENVELOPE_BYTES,
  SIG_AUTH,
  SIG_REGISTER,
  authSigningPayload,
  b64,
  canonical,
  decodeObliviousRequest,
  encodeObliviousRequest,
  pad,
  registrationSigningPayload,
  solveProofOfWork,
  unpad,
  verifyProofOfWork,
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
  username: 'dilnoza_az',
  deviceId: 1,
  registrationId: 11261,
  identityKey: b64(patterned(33, 1)),
  signedPreKey: { keyId: 1, publicKey: b64(patterned(33, 2)), signature: b64(patterned(64, 3)) },
  kyberPreKey: { keyId: 1, publicKey: b64(patterned(1568, 4)), signature: b64(patterned(64, 5)) },
  oneTimePreKeys: [{ keyId: 1, publicKey: b64(patterned(33, 6)) }],
  timestamp: 1788435744566,
};

const powContent = patterned(PADDED_ENVELOPE_BYTES, 9);
const powBucket = 7;
const powDifficulty = 12;
const powNonce = solveProofOfWork(powBucket, powContent, powDifficulty);

let powBadNonce = 0;
while (verifyProofOfWork(powBucket, powContent, powBadNonce, powDifficulty)) powBadNonce += 1;

const obliviousContent = patterned(PADDED_ENVELOPE_BYTES, 11);
const obliviousEncoded = encodeObliviousRequest(4294967295, 123456, obliviousContent);

const paddedSample = pad(utf8('Ertaga soat 10 da uchrashamizmi?'));

const vectors = {
  generatedBy: '@millygram/protocol',
  note: 'Generated file. Both implementations must agree on every value here.',
  constants: {
    paddedEnvelopeBytes: PADDED_ENVELOPE_BYTES,
    obliviousRequestBytes: OBLIVIOUS_REQUEST_BYTES,
    maxPlaintextBytes: MAX_PLAINTEXT_BYTES,
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
  },
  proofOfWork: {
    bucketId: powBucket,
    difficulty: powDifficulty,
    contentHex: hex(powContent),
    validNonce: powNonce,
    invalidNonce: powBadNonce,
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

const versionTarget = resolve('android/client/src/test/resources/gateway-libsignal-version.txt');
mkdirSync(dirname(versionTarget), { recursive: true });
writeFileSync(versionTarget, `${libsignalVersion}\n`, 'utf8');

process.stdout.write(`wrote ${target}\n`);
process.stdout.write(`wrote ${versionTarget} (${libsignalVersion})\n`);
process.stdout.write(
  `canonical cases: ${vectors.canonical.length}, base64url cases: ${vectors.base64url.length}\n`,
);
