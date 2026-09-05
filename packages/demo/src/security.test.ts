import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import Database from 'better-sqlite3';
import {
  Direction,
  IdentityKeyPair,
  KEMKeyPair,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
} from '@signalapp/libsignal-client';
import {
  LocalStore,
  MillygramClient,
  MillygramIdentityStore,
  generateRegistrationId,
  type IncomingMessage,
} from '@millygram/client';
import {
  DEFAULT_RATE_LIMITS,
  RELAY_USER_AGENT,
  startObliviousRelay,
  startServer,
  type RunningServer,
} from '@millygram/server';
import {
  OBLIVIOUS_INFO,
  OBLIVIOUS_REQUEST_BYTES,
  PADDED_ENVELOPE_BYTES,
  authSigningPayload,
  b64,
  bytes,
  canonical,
  decodeObliviousRequest,
  encodeObliviousRequest,
  pad,
  registrationSigningPayload,
  solveProofOfWork,
  unb64,
  unpad,
  verifyProofOfWork,
  type RegisterRequest,
} from '@millygram/protocol';

/** Low enough to keep the suite fast, high enough that a random nonce fails. */
const TEST_POW_DIFFICULTY = 10;

let workdir: string;
let server: RunningServer;
let counter = 0;

const unique = (label: string): { path: string; username: string } => {
  counter += 1;
  return { path: join(workdir, `${label}-${counter}.db`), username: `${label}${counter}`.slice(0, 32) };
};

/** The highest sequence a bucket currently holds, so a test can look only at what it adds. */
const bucketCursor = (bucketId: number): number => server.store.since(bucketId, 0).at(-1)?.seq ?? 0;

const testRateLimits = {
  ...DEFAULT_RATE_LIMITS,
  // Production limits exist to stop one address registering in bulk, which is
  // exactly what a test suite does. Raised here rather than relaxed by default.
  registration: { capacity: 500, refillPerSecond: 100 },
  auth: { capacity: 1000, refillPerSecond: 200 },
};

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), 'millygram-test-'));
  server = await startServer({
    host: '127.0.0.1',
    port: 0,
    databasePath: join(workdir, 'relay.db'),
    rateLimits: testRateLimits,
    powDifficulty: TEST_POW_DIFFICULTY,
  });
});

after(async () => {
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

function register(label: string, passphrase = 'a test passphrase'): Promise<MillygramClient> {
  const { path, username } = unique(label);
  return MillygramClient.register({ serverUrl: server.url, databasePath: path, passphrase, username });
}

interface RawAccount {
  body: RegisterRequest;
  identity: IdentityKeyPair;
}

/** A registration body that is internally consistent and correctly signed. */
function buildRegistration(username: string): RawAccount {
  const identity = IdentityKeyPair.generate();

  const signedPreKey = PrivateKey.generate().getPublicKey();
  const signedPreKeySignature = identity.privateKey.sign(signedPreKey.serialize());

  const kyberPreKey = KEMKeyPair.generate().getPublicKey();
  const kyberPreKeySignature = identity.privateKey.sign(kyberPreKey.serialize());

  const oneTimePreKey = PrivateKey.generate().getPublicKey();

  const unsigned: Omit<RegisterRequest, 'signature'> = {
    username,
    deviceId: 1,
    registrationId: generateRegistrationId(),
    identityKey: b64(identity.publicKey.serialize()),
    signedPreKey: { keyId: 1, publicKey: b64(signedPreKey.serialize()), signature: b64(signedPreKeySignature) },
    kyberPreKey: { keyId: 1, publicKey: b64(kyberPreKey.serialize()), signature: b64(kyberPreKeySignature) },
    oneTimePreKeys: [{ keyId: 1, publicKey: b64(oneTimePreKey.serialize()) }],
    timestamp: Date.now(),
  };

  return {
    identity,
    body: { ...unsigned, signature: b64(identity.privateKey.sign(registrationSigningPayload(unsigned))) },
  };
}

const postJson = (path: string, body: unknown): Promise<Response> =>
  fetch(`${server.url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

const submit = (body: unknown): Promise<Response> =>
  fetch(`${server.url}/v1/messages`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

describe('the relay rejects forged credentials', () => {
  test('a registration signature that does not cover the username is refused', async () => {
    const { body } = buildRegistration('honest_user');
    // The signature is genuine; it was simply made over a different username.
    const response = await postJson('/v1/accounts', { ...body, username: 'impostor_user' });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'invalid_signature');
  });

  test('a prekey signed by a different identity is refused', async () => {
    const { body } = buildRegistration('prekey_victim');
    const attacker = IdentityKeyPair.generate();
    const foreignKey = PrivateKey.generate().getPublicKey();

    const response = await postJson('/v1/accounts', {
      ...body,
      signedPreKey: {
        keyId: 1,
        publicKey: b64(foreignKey.serialize()),
        signature: b64(attacker.privateKey.sign(foreignKey.serialize())),
      },
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'invalid_signature');
  });

  test('an auth challenge cannot be replayed', async () => {
    const { body, identity } = buildRegistration(unique('replay').username);
    const registered = await postJson('/v1/accounts', body);
    assert.equal(registered.status, 201);
    const { aci } = (await registered.json()) as { aci: string };

    const challenge = (await (await fetch(`${server.url}/v1/accounts/challenge?aci=${aci}`)).json()) as {
      nonce: string;
    };
    const answer = {
      aci,
      deviceId: 1,
      nonce: challenge.nonce,
      signature: b64(identity.privateKey.sign(authSigningPayload(aci, 1, unb64(challenge.nonce)))),
    };

    assert.equal((await postJson('/v1/accounts/auth', answer)).status, 200);
    assert.equal(
      (await postJson('/v1/accounts/auth', answer)).status,
      401,
      'the same nonce must never authenticate twice',
    );
  });
});

describe('anonymous submission is paid for in work', () => {
  test('an envelope without valid proof of work is refused', async () => {
    const recipient = await register('powreject');
    const content = randomBytes(PADDED_ENVELOPE_BYTES);

    // Find a nonce that definitely fails, so the assertion is not probabilistic.
    let badNonce = 0;
    while (verifyProofOfWork(recipient.bucketId, content, badNonce, TEST_POW_DIFFICULTY)) badNonce += 1;

    const response = await submit({
      bucketId: recipient.bucketId,
      content: b64(content),
      nonce: badNonce,
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'insufficient_proof_of_work');
    recipient.close();
  });

  test('proof of work is bound to the bucket it was solved for', async () => {
    const first = await register('powbindone');
    const second = await register('powbindtwo');
    const content = randomBytes(PADDED_ENVELOPE_BYTES);

    const nonce = solveProofOfWork(first.bucketId, content, TEST_POW_DIFFICULTY);
    assert.equal((await submit({ bucketId: first.bucketId, content: b64(content), nonce })).status, 202);

    if (second.bucketId !== first.bucketId) {
      const replayed = await submit({ bucketId: second.bucketId, content: b64(content), nonce });
      assert.equal(replayed.status, 400, 'work solved for one bucket must not pay for another');
    }

    first.close();
    second.close();
  });

  test('a submission carries no identifying header at all', async () => {
    const recipient = await register('anonsubmit');
    const content = randomBytes(PADDED_ENVELOPE_BYTES);
    const nonce = solveProofOfWork(recipient.bucketId, content, TEST_POW_DIFFICULTY);

    // No Authorization header, no access key, no cookie: the relay accepts this
    // and has nothing it could record about who sent it.
    const response = await submit({ bucketId: recipient.bucketId, content: b64(content), nonce });

    assert.equal(response.status, 202);
    recipient.close();
  });
});

describe('abuse resistance', () => {
  test('a failed proof of work does not consume the target bucket budget', async () => {
    const recipient = await register('powbudget');
    const content = randomBytes(PADDED_ENVELOPE_BYTES);

    let badNonce = 0;
    while (verifyProofOfWork(recipient.bucketId, content, badNonce, TEST_POW_DIFFICULTY)) badNonce += 1;

    // Far more than the bucket's burst capacity, all of it worthless. If the
    // limiter were consumed before the proof of work were checked, this alone
    // would deny delivery to every member of the bucket for free.
    for (let attempt = 0; attempt < 80; attempt += 1) {
      const response = await submit({
        bucketId: recipient.bucketId,
        content: b64(content),
        nonce: badNonce,
      });
      assert.equal(response.status, 400, 'garbage must be refused on its merits, not rate limited');
    }

    // A genuine submission must still get through afterwards.
    const good = randomBytes(PADDED_ENVELOPE_BYTES);
    const nonce = solveProofOfWork(recipient.bucketId, good, TEST_POW_DIFFICULTY);
    const accepted = await submit({ bucketId: recipient.bucketId, content: b64(good), nonce });

    assert.equal(accepted.status, 202, 'a paid-for submission must survive a flood of unpaid ones');
    recipient.close();
  });

  test('a captured submission cannot be replayed', async () => {
    const recipient = await register('replaysubmit');
    const content = randomBytes(PADDED_ENVELOPE_BYTES);
    const nonce = solveProofOfWork(recipient.bucketId, content, TEST_POW_DIFFICULTY);
    const body = { bucketId: recipient.bucketId, content: b64(content), nonce };

    assert.equal((await submit(body)).status, 202);

    // The proof of work only costs anything the first time. Without replay
    // defence an observer could resend this indefinitely and every member of
    // the bucket would download it again each time.
    const replayed = await submit(body);
    assert.equal(replayed.status, 409);
    assert.equal(((await replayed.json()) as { error: string }).error, 'duplicate_submission');

    recipient.close();
  });

  test('one account cannot drain another account of one-time prekeys', async () => {
    const victim = await register('drainvictim');
    const attacker = await register('drainattacker');

    const token = await (attacker as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();

    let served = 0;
    let refused = 0;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await fetch(`${server.url}/v1/keys/${victim.aci}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      if (response.status === 200) served += 1;
      if (response.status === 429) refused += 1;
      await response.arrayBuffer();
    }

    assert.ok(refused > 0, 'bundle fetches must be throttled per caller');
    assert.ok(
      served < 40,
      `a single caller served ${served} bundles would drain the victim's one-time prekeys`,
    );

    victim.close();
    attacker.close();
  });

  test('a drained account can still be messaged, with the ratchet intact', async () => {
    const victim = await register('drainedvictim');
    const sender = await register('drainedsender');

    // Drained through the store rather than the API, because the rate limits
    // that make this take half an hour over the wire are the subject of the
    // test above, not this one. What matters here is the state they slow the
    // attacker down from reaching, not how long it takes.
    while (server.store.takeOneTimePreKey(victim.aci)) {
      /* empty the pool */
    }
    assert.equal(server.store.countOneTimePreKeys(victim.aci), 0, 'the pool must actually be empty');

    // Exhaustion must degrade forward secrecy for the opening message, not
    // deny service. If a session could not be built without a one-time prekey,
    // draining someone would stop anyone new from ever reaching them.
    await sender.send(victim.username, 'no one-time prekey left');

    const inbox: IncomingMessage[] = [];
    await victim.catchUp((message) => {
      inbox.push(message);
    });

    assert.equal(inbox.length, 1, 'a drained account must still receive');
    assert.equal(inbox[0]!.body, 'no one-time prekey left');
    assert.equal(inbox[0]!.senderAci, sender.aci, 'sealed sender still resolves');

    // And the session that came out of that bundle has to keep working.
    await victim.send(sender.aci, 'reply on the drained session');
    const back: IncomingMessage[] = [];
    await sender.catchUp((message) => {
      back.push(message);
    });
    assert.equal(back.length, 1);
    assert.equal(back[0]!.body, 'reply on the drained session');

    assert.equal(
      await sender.safetyNumber(victim.aci),
      await victim.safetyNumber(sender.aci),
      'a bundle served without a one-time prekey must not change either identity',
    );

    victim.close();
    sender.close();
  });
});

describe('bearer tokens', () => {
  test('a token with a tampered payload is refused', async () => {
    const client = await register('tokentamper');
    const token = await (client as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();

    const [payload, mac] = token.split('.') as [string, string];
    const decoded = Buffer.from(payload, 'base64url');
    // Push the expiry far into the future without touching the MAC.
    decoded.writeBigUInt64BE(BigInt(Date.now() + 10 * 365 * 24 * 3600 * 1000), 17);
    const forged = `${decoded.toString('base64url')}.${mac}`;

    const response = await fetch(`${server.url}/v1/keys/count`, {
      headers: { authorization: `Bearer ${forged}` },
    });

    assert.equal(response.status, 401);
    client.close();
  });

  test('a token naming an account that does not exist is refused', async () => {
    const client = await register('tokenghost');
    const token = await (client as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();

    // Same structure, different account id. The MAC will not match, but the
    // account check is the backstop that matters if a key ever leaks.
    const [payload] = token.split('.') as [string];
    const decoded = Buffer.from(payload, 'base64url');
    decoded.write('ffffffffffffffffffffffffffffffff', 0, 'hex');

    const response = await fetch(`${server.url}/v1/keys/count`, {
      headers: { authorization: `Bearer ${decoded.toString('base64url')}.x` },
    });

    assert.equal(response.status, 401);
    client.close();
  });
});

describe('the relay cannot tell who an envelope is for', () => {
  test('a bucket peer receives the envelope and cannot open it', async () => {
    const isolated = mkdtempSync(join(tmpdir(), 'millygram-bucket-'));
    // A dedicated relay with a small bucket, so the three accounts below are
    // guaranteed to share one.
    const shared = await startServer({
      host: '127.0.0.1',
      port: 0,
      databasePath: join(isolated, 'relay.db'),
      rateLimits: testRateLimits,
      powDifficulty: TEST_POW_DIFFICULTY,
      bucketSize: 8,
    });

    const make = (name: string) =>
      MillygramClient.register({
        serverUrl: shared.url,
        databasePath: join(isolated, `${name}.db`),
        passphrase: `${name} passphrase`,
        username: name,
      });

    const alisher = await make('alisher');
    const nodira = await make('nodira');
    const eavesdropper = await make('eavesdropper');

    assert.equal(alisher.bucketId, nodira.bucketId);
    assert.equal(alisher.bucketId, eavesdropper.bucketId);

    const delivered: IncomingMessage[] = [];
    const overheard: IncomingMessage[] = [];
    await nodira.connect((message) => {
      delivered.push(message);
    });
    await eavesdropper.connect((message) => {
      overheard.push(message);
    });

    await alisher.send('nodira', 'a private message');

    const deadline = Date.now() + 5000;
    while (delivered.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));

    // Give the peer the same chance to process the envelope it also received.
    await eavesdropper.catchUp((message) => {
      overheard.push(message);
    });

    assert.equal(delivered.length, 1, 'the intended recipient must receive it');
    assert.equal(delivered[0]!.body, 'a private message');
    assert.equal(overheard.length, 0, 'a bucket peer must receive the envelope and get nothing from it');

    assert.equal(
      shared.store.since(alisher.bucketId, 0).length,
      1,
      'the envelope sits in a bucket shared by all three accounts',
    );

    alisher.close();
    nodira.close();
    eavesdropper.close();
    await shared.close();
    rmSync(isolated, { recursive: true, force: true });
  });

  test('the envelope table has no column naming a sender or a recipient', () => {
    const columns = Object.keys(server.store.dumpTable('envelopes')[0] ?? {});
    assert.ok(columns.length > 0, 'expected at least one envelope to inspect');
    for (const column of columns) {
      assert.ok(
        !/aci|sender|recipient|destination|user/i.test(column),
        `envelopes.${column} would identify a party to the conversation`,
      );
    }
  });
});

describe('message integrity and padding', () => {
  test('flipping one byte of an envelope makes it undecryptable', async () => {
    const sender = await register('tsender');
    const receiver = await register('treceiver');
    const cursor = bucketCursor(receiver.bucketId);

    await sender.send(receiver.username, 'a message nobody should be able to alter');

    const queued = server.store.since(receiver.bucketId, cursor);
    assert.equal(queued.length, 1);
    const envelope = queued[0]!;

    // Aim inside the real ciphertext, not the random filler after it. The
    // filler is deliberately unauthenticated — it is discarded before
    // decryption, so altering it changes nothing — and integrity here means the
    // ciphertext itself cannot be touched.
    const corrupted = Buffer.from(envelope.content);
    const ciphertextLength = corrupted.readUInt32BE(0);
    const target = 4 + Math.floor(ciphertextLength / 2);
    corrupted.writeUInt8(corrupted.readUInt8(target) ^ 0x01, target);

    const opened = await receiver.openEnvelope({
      seq: envelope.seq,
      content: b64(corrupted),
      arrivedAt: envelope.arrived_at,
    });
    assert.equal(opened, null, 'a modified envelope must not decrypt');

    sender.close();
    receiver.close();
  });

  test('the same text sent twice produces different ciphertext', async () => {
    const sender = await register('rsender');
    const receiver = await register('rreceiver');
    const cursor = bucketCursor(receiver.bucketId);

    await sender.send(receiver.username, 'identical text');
    await sender.send(receiver.username, 'identical text');

    const queued = server.store.since(receiver.bucketId, cursor);
    assert.equal(queued.length, 2);
    assert.notDeepEqual(queued[0]!.content, queued[1]!.content, 'the ratchet must derive a fresh key each time');

    sender.close();
    receiver.close();
  });

  test('a short message and a long one are the same size on the wire', async () => {
    const sender = await register('padsender');
    const receiver = await register('padreceiver');
    const cursor = bucketCursor(receiver.bucketId);

    // Includes the session-establishing message, which carries prekey material
    // and would otherwise be much larger than the rest.
    await sender.send(receiver.username, 'setting up the session');
    await sender.send(receiver.username, 'ha');
    await sender.send(receiver.username, 'x'.repeat(3000));

    const queued = server.store.since(receiver.bucketId, cursor);
    assert.equal(queued.length, 3);
    assert.deepEqual(
      [...new Set(queued.map((row) => row.content.length))],
      [PADDED_ENVELOPE_BYTES],
      'every envelope must be exactly the padded size, whatever it carries',
    );

    sender.close();
    receiver.close();
  });

  test('padding round-trips and hides the original length', () => {
    const short = Buffer.from('ha', 'utf8');
    const long = Buffer.from('x'.repeat(3000), 'utf8');

    assert.equal(pad(short).length, PADDED_ENVELOPE_BYTES);
    assert.equal(pad(long).length, PADDED_ENVELOPE_BYTES);
    assert.deepEqual(Buffer.from(unpad(pad(short))), short);
    assert.deepEqual(Buffer.from(unpad(pad(long))), long);
  });

  test('the relay refuses an envelope that is not padded', async () => {
    const recipient = await register('unpadded');
    const content = randomBytes(512);
    const nonce = solveProofOfWork(recipient.bucketId, content, TEST_POW_DIFFICULTY);

    const response = await submit({ bucketId: recipient.bucketId, content: b64(content), nonce });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'envelope_must_be_padded');
    recipient.close();
  });
});

describe('encoding is canonical on both implementations', () => {
  test('non-canonical base64url is rejected rather than silently reinterpreted', () => {
    // Node's decoder accepts every one of these and quietly returns bytes.
    // Java's rejects most. Left alone, the two implementations disagree about
    // what a valid wire value even is.
    for (const input of ['A', 'AAAAA', 'AAAA=', 'AAAA==', 'AA A', 'AA\nA', '+/+/', 'AA%3D']) {
      assert.throws(
        () => unb64(input),
        RangeError,
        `must reject ${JSON.stringify(input)}`,
      );
    }
  });

  test('canonical values still round-trip', () => {
    for (const bytesIn of [new Uint8Array(0), randomBytes(1), randomBytes(2), randomBytes(33)]) {
      assert.deepEqual(Buffer.from(unb64(b64(bytesIn))), Buffer.from(bytesIn));
    }
  });

  test('integers above the shared bound are refused', () => {
    // Kotlin's Long would happily encode these; TypeScript cannot represent
    // them exactly. A payload only one implementation can produce is a payload
    // only one implementation can verify.
    assert.throws(() => canonical('millygram/test/v1', [Number.MAX_SAFE_INTEGER + 1]), RangeError);
    assert.throws(() => canonical('millygram/test/v1', [-1]), RangeError);
    assert.doesNotThrow(() => canonical('millygram/test/v1', [Number.MAX_SAFE_INTEGER]));
  });
});

describe('the local vault', () => {
  test('the wrong passphrase cannot open it', () => {
    const { path } = unique('vault');
    LocalStore.open(path, 'the real passphrase').close();
    assert.throws(() => LocalStore.open(path, 'not the real passphrase'), /wrong passphrase/);
  });

  test('a stored value cannot be relocated to a different key', () => {
    const { path } = unique('aad');
    const store = LocalStore.open(path, 'aad passphrase');
    store.setMetaString('harmless_value', 'nothing important');
    store.setMetaString('identity_pin', 'the value that matters');
    store.close();

    // An attacker with write access moves one valid ciphertext on top of
    // another. Without binding each value to its row this would succeed
    // silently, and swapping a pinned identity is exactly the attack.
    const raw = new Database(path);
    const source = raw.prepare("SELECT value FROM meta WHERE key = 'harmless_value'").get() as { value: Buffer };
    raw.prepare("UPDATE meta SET value = ? WHERE key = 'identity_pin'").run(source.value);
    raw.close();

    const reopened = LocalStore.open(path, 'aad passphrase');
    assert.throws(() => reopened.getMeta('identity_pin'), /unable to authenticate|unsupported state/i);
    reopened.close();
  });
});

describe('identity pinning', () => {
  test('a changed identity key for a known contact is not trusted', async () => {
    const { path } = unique('pinning');
    const store = LocalStore.open(path, 'pinning passphrase');
    const identityStore = new MillygramIdentityStore(store, IdentityKeyPair.generate(), generateRegistrationId());

    const peer = ProtocolAddress.new('11111111-2222-3333-4444-555555555555', 1);
    const original = IdentityKeyPair.generate().publicKey;
    const swapped = IdentityKeyPair.generate().publicKey;

    await identityStore.saveIdentity(peer, original);

    assert.equal(await identityStore.isTrustedIdentity(peer, original, Direction.Receiving), true);
    assert.equal(
      await identityStore.isTrustedIdentity(peer, swapped, Direction.Receiving),
      false,
      'a relay swapping a contact key must be detected, not accepted',
    );

    store.close();
  });
});

describe('a malicious gateway cannot read a conversation undetected', () => {
  test('substituting an identity key costs delivery and is reported when the real contact writes', async () => {
    const bob = await register('mitmbob');
    const alice = await register('mitmalice');

    // The operator tampers with their own database — no protocol violation
    // needed, just an UPDATE.
    //
    // Swapping the identity key alone is not enough: the client checks that the
    // signed and Kyber prekeys are signed by the advertised identity, and a
    // half-substituted bundle is rejected outright with "not signed by the
    // advertised identity key". So the attacker re-signs both prekeys with
    // their own key, which anyone holding the database can do.
    //
    // The poisoning is applied only while Alice fetches, then reverted. A real
    // operator would serve one bundle to Alice and leave Bob's record intact,
    // because Bob authenticates with his real key and a permanently altered
    // record would simply lock him out — announcing the attack.
    const attacker = IdentityKeyPair.generate();
    const raw = new Database(join(workdir, 'relay.db'));
    const before = {
      identity: (raw.prepare('SELECT identity_key AS k FROM accounts WHERE aci = ?')
        .get(bob.aci) as { k: Buffer }).k,
      signed: (raw.prepare('SELECT signature AS k FROM signed_prekeys WHERE aci = ?')
        .get(bob.aci) as { k: Buffer }).k,
      kyber: (raw.prepare('SELECT signature AS k FROM kyber_prekeys WHERE aci = ?')
        .get(bob.aci) as { k: Buffer }).k,
    };
    const signedPub = (raw.prepare('SELECT public_key AS k FROM signed_prekeys WHERE aci = ?')
      .get(bob.aci) as { k: Buffer }).k;
    const kyberPub = (raw.prepare('SELECT public_key AS k FROM kyber_prekeys WHERE aci = ?')
      .get(bob.aci) as { k: Buffer }).k;

    raw.prepare('UPDATE accounts SET identity_key = ? WHERE aci = ?')
      .run(Buffer.from(attacker.publicKey.serialize()), bob.aci);
    raw.prepare('UPDATE signed_prekeys SET signature = ? WHERE aci = ?')
      .run(Buffer.from(attacker.privateKey.sign(new Uint8Array(signedPub))), bob.aci);
    raw.prepare('UPDATE kyber_prekeys SET signature = ? WHERE aci = ?')
      .run(Buffer.from(attacker.privateKey.sign(new Uint8Array(kyberPub))), bob.aci);

    // Alice has never spoken to Bob, so she has nothing pinned and accepts the
    // bundle. This is the trust-on-first-use window every such system has.
    await alice.send(bob.username, 'meant only for Bob');

    raw.prepare('UPDATE accounts SET identity_key = ? WHERE aci = ?').run(before.identity, bob.aci);
    raw.prepare('UPDATE signed_prekeys SET signature = ? WHERE aci = ?').run(before.signed, bob.aci);
    raw.prepare('UPDATE kyber_prekeys SET signature = ? WHERE aci = ?').run(before.kyber, bob.aci);
    raw.close();

    // What the operator cannot do is stay invisible. The message was sealed to
    // a key Bob does not hold, so Bob cannot open it: passive interception
    // costs the operator delivery outright.
    const inbox: IncomingMessage[] = [];
    await bob.catchUp((message) => {
      inbox.push(message);
    });
    assert.equal(inbox.length, 0, 'a substituted key must not still decrypt for Bob');

    // And it does not survive contact with the real Bob. Alice now has the
    // attacker's key pinned for Bob's account, so the moment Bob actually
    // writes to her, his genuine identity fails that pin. Without this being
    // reported the message would simply vanish into the same silence as every
    // envelope addressed to another bucket member, and the attack would cost
    // the operator nothing but one undelivered message.
    const flagged: unknown[] = [];
    alice.onUntrustedIdentity = (envelope) => flagged.push(envelope);

    await bob.send(alice.aci, 'the real Bob, writing back');

    const alicesInbox: IncomingMessage[] = [];
    await alice.catchUp((message) => {
      alicesInbox.push(message);
    });

    assert.equal(alicesInbox.length, 0, 'a message under an unpinned identity must not be delivered');
    assert.equal(flagged.length, 1, 'the substitution must be reported, not swallowed as bucket noise');

    alice.close();
    bob.close();
  });
});

describe('the ratchet survives concurrent use', () => {
  test('two sends issued at once are both delivered', async () => {
    const sender = await register('racesend');
    const receiver = await register('racerecv');

    // Establish the session first, so this exercises concurrent use of an
    // existing ratchet rather than concurrent session setup.
    await sender.send(receiver.username, 'warm up');
    await receiver.catchUp(() => {});

    // The Double Ratchet is read-modify-write. Unserialised, both of these
    // encrypt from the same session state and the later write discards the
    // earlier ratchet advance: both calls resolve, the relay accepts both
    // envelopes, and the recipient can only follow one chain — so one message
    // is lost with nothing reporting a failure.
    await Promise.all([sender.send(receiver.aci, 'one'), sender.send(receiver.aci, 'two')]);

    const inbox: IncomingMessage[] = [];
    await receiver.catchUp((message) => {
      inbox.push(message);
    });

    assert.deepEqual(
      inbox.map((message) => message.body).sort(),
      ['one', 'two'],
      'a concurrent send must not be silently dropped',
    );

    sender.close();
    receiver.close();
  });
});

describe('oblivious submission', () => {
  test('a message sent through the relay is delivered normally', async () => {
    const relay = await startObliviousRelay({ gatewayUrl: server.url, host: '127.0.0.1', port: 0 });

    const senderId = unique('obsender');
    const receiverId = unique('obreceiver');

    const sender = await MillygramClient.register({
      serverUrl: server.url,
      databasePath: senderId.path,
      passphrase: 'oblivious sender',
      username: senderId.username,
      obliviousRelayUrl: relay.url,
    });
    const receiver = await MillygramClient.register({
      serverUrl: server.url,
      databasePath: receiverId.path,
      passphrase: 'oblivious receiver',
      username: receiverId.username,
    });

    const inbox: IncomingMessage[] = [];
    await sender.send(receiver.username, 'sent the oblivious way');
    await receiver.catchUp((message) => {
      inbox.push(message);
    });

    assert.equal(inbox.length, 1);
    assert.equal(inbox[0]!.body, 'sent the oblivious way');
    assert.equal(inbox[0]!.senderAci, sender.aci, 'sealed sender still resolves end to end');

    sender.close();
    receiver.close();
    await relay.close();
  });

  test('the relay forwards no client-identifying header', async () => {
    const seen: { headers: Record<string, string>; bodyLength: number }[] = [];

    const fakeGateway = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        seen.push({
          headers: Object.fromEntries(
            Object.entries(request.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(',') : String(v)]),
          ),
          bodyLength: Buffer.concat(chunks).length,
        });
        response.writeHead(202).end();
      });
    });
    await new Promise<void>((resolve) => fakeGateway.listen(0, '127.0.0.1', resolve));
    const gatewayPort = (fakeGateway.address() as { port: number }).port;

    const relay = await startObliviousRelay({
      gatewayUrl: `http://127.0.0.1:${gatewayPort}`,
      host: '127.0.0.1',
      port: 0,
    });

    // Distinctive values, so a leak through any header name — including ones
    // this test never thought to list — is still caught.
    const sentinels = {
      'x-forwarded-for': '203.0.113.7',
      forwarded: 'for=198.51.100.9',
      'x-real-ip': '192.0.2.44',
      cookie: 'session=Sent1nelCookie',
      authorization: 'Bearer Sent1nelToken',
      'user-agent': 'MillyGram/1.0 Sent1nelAgent',
      referer: 'https://sent1nel.invalid/page',
      'accept-language': 'uz-Sent1nel',
    };

    const response = await fetch(relay.url, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', ...sentinels },
      body: new Uint8Array(randomBytes(64)),
    });

    assert.equal(response.status, 202);
    assert.equal(seen.length, 1);

    const forwarded = seen[0]!.headers;

    // The property that matters is not a list of banned names: it is that no
    // value supplied by the client reaches the gateway at all.
    for (const [name, value] of Object.entries(sentinels)) {
      for (const [forwardedName, forwardedValue] of Object.entries(forwarded)) {
        assert.ok(
          !forwardedValue.includes(value),
          `the relay leaked ${name} to the gateway as ${forwardedName}`,
        );
      }
    }

    for (const banned of ['x-forwarded-for', 'forwarded', 'x-real-ip', 'cookie', 'authorization', 'referer']) {
      assert.equal(forwarded[banned], undefined, `the relay leaked ${banned} to the gateway`);
    }

    // The relay's own signature is pinned, so every upstream request looks the
    // same regardless of who caused it.
    assert.equal(forwarded['user-agent'], RELAY_USER_AGENT);
    assert.equal(forwarded['content-type'], 'application/octet-stream');
    assert.equal(seen[0]!.bodyLength, 64, 'the sealed body itself is forwarded unchanged');

    await relay.close();
    fakeGateway.closeAllConnections();
    await new Promise<void>((resolve) => fakeGateway.close(() => resolve()));
  });

  test('the gateway rejects a blob it cannot open', async () => {
    const response = await fetch(`${server.url}/v1/oblivious`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: new Uint8Array(randomBytes(OBLIVIOUS_REQUEST_BYTES + 49)),
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'undecryptable');
  });

  test('the gateway rejects a sealed request of the wrong shape', async () => {
    const key = (await (await fetch(`${server.url}/v1/oblivious-key`)).json()) as { publicKey: string };
    const gatewayKey = PublicKey.deserialize(unb64(key.publicKey));

    // Correctly sealed and correctly addressed, but not the fixed request layout.
    const sealed = gatewayKey.seal(bytes(randomBytes(128)), OBLIVIOUS_INFO);

    const response = await fetch(`${server.url}/v1/oblivious`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: sealed,
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'malformed_oblivious_request');
  });

  test('the oblivious path enforces proof of work like the direct one', async () => {
    const recipient = await register('obpow');
    const key = (await (await fetch(`${server.url}/v1/oblivious-key`)).json()) as { publicKey: string };
    const gatewayKey = PublicKey.deserialize(unb64(key.publicKey));

    const content = randomBytes(PADDED_ENVELOPE_BYTES);
    let badNonce = 0;
    while (verifyProofOfWork(recipient.bucketId, content, badNonce, TEST_POW_DIFFICULTY)) badNonce += 1;

    const sealed = gatewayKey.seal(encodeObliviousRequest(recipient.bucketId, badNonce, content), OBLIVIOUS_INFO);

    const response = await fetch(`${server.url}/v1/oblivious`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: sealed,
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'insufficient_proof_of_work');
    recipient.close();
  });

  test('a sealed submission is a constant size whatever it carries', () => {
    const key = PrivateKey.generate().getPublicKey();
    const first = encodeObliviousRequest(1, 1, randomBytes(PADDED_ENVELOPE_BYTES));
    const second = encodeObliviousRequest(4294967295, 4294967295, randomBytes(PADDED_ENVELOPE_BYTES));

    assert.equal(first.length, OBLIVIOUS_REQUEST_BYTES);
    assert.equal(
      key.seal(first, OBLIVIOUS_INFO).length,
      key.seal(second, OBLIVIOUS_INFO).length,
      'sealed size must not vary with the request it carries',
    );
  });

  test('the oblivious request layout round-trips exactly', () => {
    const content = randomBytes(PADDED_ENVELOPE_BYTES);
    const decoded = decodeObliviousRequest(encodeObliviousRequest(4294967295, 123456, content));

    assert.ok(decoded);
    assert.equal(decoded.bucketId, 4294967295);
    assert.equal(decoded.nonce, 123456);
    assert.deepEqual(Buffer.from(decoded.content), content);

    assert.equal(decodeObliviousRequest(randomBytes(OBLIVIOUS_REQUEST_BYTES - 1)), null);
    assert.equal(decodeObliviousRequest(randomBytes(OBLIVIOUS_REQUEST_BYTES + 1)), null);
  });
});
