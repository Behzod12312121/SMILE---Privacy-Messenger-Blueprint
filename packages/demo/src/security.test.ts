import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
  DEFAULT_INBOUND_POW_ESCALATION,
  type ServerConfig,
  RELAY_USER_AGENT,
  startObliviousRelay,
  startServer,
  type RateLimits,
  type RunningServer,
} from '@millygram/server';
import {
  MAX_GROUPS,
  OBLIVIOUS_INFO,
  OBLIVIOUS_REQUEST_BYTES,
  OBLIVIOUS_SEALED_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_GROUP_REVISION,
  PADDED_ENVELOPE_BYTES,
  PADDED_PAYLOAD_BYTES,
  authSigningPayload,
  b64,
  bytes,
  canonical,
  decodeObliviousRequest,
  encodeObliviousRequest,
  pad,
  PREKEY_ROTATION_MS,
  recoverySigningPayload,
  registrationSigningPayload,
  solveRegistrationWork,
  solveProofOfWork,
  unb64,
  unpad,
  verifyProofOfWork,
  verifyRegistrationWork,
  usernameCandidates,
  createUsernameLink,
  usernameFromLink,
  USERNAME_LINK_PREFIX,
  usernameHash,
  usernameProof,
  isValidUsername,
  type RegisterRequest,
} from '@millygram/protocol';

/** Low enough to keep the suite fast, high enough that a random nonce fails. */
const TEST_POW_DIFFICULTY = 10;
/** Registration work, lowered so the suite is not spending seconds per account. */
const TEST_REGISTRATION_POW = 8;

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
    registrationPowDifficulty: TEST_REGISTRATION_POW,
    // Stands in for the SMS account an operator would have to provide. Nothing
    // in this repository can send one, which is the point of the seam.
    sendRecoveryCode: async (phoneNumber: string, code: string) => {
      lastCode = code;
      codesSent.push({ phoneNumber, code });
      // A real SMS gateway is an HTTP call to somebody else's service and
      // takes time. Standing in for it with an instant function would hide
      // any timing difference between an attached number and an unattached
      // one, which is precisely what the enumeration test needs to see.
      await new Promise((resolve) => setTimeout(resolve, SMS_GATEWAY_DELAY_MS));
    },
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
  /** The handle behind body.usernameHash, which only the client ever knows. */
  username: string;
}

/** A registration body that is internally consistent and correctly signed. */
let lastCode = '';
const codesSent: { phoneNumber: string; code: string }[] = [];

/** A signed request to rebind an account to a fresh identity. */
function recoveryBody(phoneNumber: string, code: string): Record<string, unknown> {
  const identity = IdentityKeyPair.generate();

  const signedPreKey = PrivateKey.generate().getPublicKey();
  const kyberPreKey = KEMKeyPair.generate().getPublicKey();
  const oneTimePreKey = PrivateKey.generate().getPublicKey();

  const unsigned = {
    phoneNumber,
    code,
    registrationId: generateRegistrationId(),
    identityKey: b64(identity.publicKey.serialize()),
    signedPreKey: {
      keyId: 2,
      publicKey: b64(signedPreKey.serialize()),
      signature: b64(identity.privateKey.sign(signedPreKey.serialize())),
    },
    kyberPreKey: {
      keyId: 2,
      publicKey: b64(kyberPreKey.serialize()),
      signature: b64(identity.privateKey.sign(kyberPreKey.serialize())),
    },
    oneTimePreKeys: [{ keyId: 2, publicKey: b64(oneTimePreKey.serialize()) }],
    timestamp: Date.now(),
  };

  return {
    ...unsigned,
    signature: b64(identity.privateKey.sign(recoverySigningPayload(unsigned as never))),
  };
}

function buildRegistration(nickname: string): RawAccount {
  // The gateway is never told the name, so a test body carries the same thing a
  // real client sends: the hash of a handle, and a proof of knowing it.
  const username = usernameCandidates(nickname)[0]!;
  const identity = IdentityKeyPair.generate();

  const signedPreKey = PrivateKey.generate().getPublicKey();
  const signedPreKeySignature = identity.privateKey.sign(signedPreKey.serialize());

  const kyberPreKey = KEMKeyPair.generate().getPublicKey();
  const kyberPreKeySignature = identity.privateKey.sign(kyberPreKey.serialize());

  const oneTimePreKey = PrivateKey.generate().getPublicKey();

  const unsigned: Omit<RegisterRequest, 'signature' | 'workNonce'> = {
    usernameHash: b64(usernameHash(username)),
    usernameProof: b64(usernameProof(username)),
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
    username,
    body: {
      ...unsigned,
      signature: b64(identity.privateKey.sign(registrationSigningPayload(unsigned))),
      workNonce: solveRegistrationWork(registrationSigningPayload(unsigned), TEST_REGISTRATION_POW),
    },
  };
}

const postJson = (path: string, body: unknown): Promise<Response> =>
  fetch(`${server.url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

/**
 * Re-solves the work for a body that a test has altered.
 *
 * Work is checked before signatures, because it is the cheaper of the two and
 * is what makes flooding the endpoint expensive. A test that tampers with a
 * registration therefore has to pay for the tampered version, or it never
 * reaches the check it is actually about.
 */
const reworked = <T extends Record<string, unknown>>(body: T): T => {
  const { signature, workNonce, ...unsigned } = body as unknown as RegisterRequest;
  return {
    ...body,
    workNonce: solveRegistrationWork(
      registrationSigningPayload(unsigned),
      TEST_REGISTRATION_POW,
    ),
  };
};

const submit = (body: unknown): Promise<Response> =>
  fetch(`${server.url}/v1/messages`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

/** How long the stand-in SMS gateway takes to answer. See sendRecoveryCode. */
const SMS_GATEWAY_DELAY_MS = 400;

describe('recovering an account by phone number', () => {
  const numberFor = (n: number) => `+99890${String(1000000 + n).slice(0, 7)}`;

  const attach = async (client: MillygramClient, phoneNumber: string) => {
    const token = await (client as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();
    return fetch(`${server.url}/v1/account/recovery-number`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber }),
    });
  };

  const start = (phoneNumber: string) =>
    postJson('/v1/recovery/start', { phoneNumber });

  /** The identity key the gateway is currently handing out for an account. */
  const publishedIdentityKey = async (caller: MillygramClient, aci: string): Promise<string> => {
    const token = await (caller as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();
    const response = await fetch(`${server.url}/v1/keys/${aci}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(response.status, 200);
    return ((await response.json()) as { identityKey: string }).identityKey;
  };

  test('a number that is attached and one that is not answer alike', async () => {
    const owner = await register('recovera');
    const attached = numberFor(11);
    assert.equal((await attach(owner, attached)).status, 204);

    const known = await start(attached);
    const unknown = await start(numberFor(12));

    // Answering differently would tell anyone holding a list of numbers which
    // of them use this service — the enumeration that not asking for a number
    // at signup exists to prevent. Giving it away here instead would be an odd
    // way to spend that.
    assert.equal(known.status, unknown.status);
    assert.equal(known.status, 202);
    assert.equal(await known.text(), await unknown.text());

    owner.close();
  });

  test('a number already in use cannot be taken from the account that holds it', async () => {
    const owner = await register('recoverown');
    const thief = await register('recoverthief');
    const number = numberFor(51);

    assert.equal((await attach(owner, number)).status, 204);

    // Nothing here proves who owns the number — that is only checked at
    // recovery — so the first claim has to stand. An upsert would make this
    // request a way to cut any user off from ever recovering: type their
    // number, take the row, and the only person who learns about it is the one
    // who lost their phone and finds the code going somewhere else.
    const stolen = await attach(thief, number);
    assert.equal(stolen.status, 409, 'a stranger took over a number already in use');

    // And the number still recovers who it always did.
    await start(number);
    const response = await postJson('/v1/recovery/complete', recoveryBody(number, lastCode));
    assert.equal(response.status, 200);
    // The gateway cannot say what the handle is — it has only ever held the
    // hash — so what recovery returns is the hash, and the device confirms the
    // name against it without asking anybody.
    const recovered = (await response.json()) as { usernameHash: string };
    assert.equal(
      recovered.usernameHash,
      b64(usernameHash(owner.username)),
      'the number recovered the wrong account',
    );

    owner.close();
    thief.close();
  });

  test('a user can re-enter their own number', async () => {
    const owner = await register('recoverreset');
    const number = numberFor(61);

    // Refusing a number in use must not refuse the person already using it, or
    // correcting anything about your own entry becomes impossible.
    assert.equal((await attach(owner, number)).status, 204);
    assert.equal((await attach(owner, number)).status, 204);

    // And moving to a different number releases the old one.
    const moved = numberFor(62);
    assert.equal((await attach(owner, moved)).status, 204);

    const other = await register('recoverpickup');
    assert.equal((await attach(other, number)).status, 204, 'an abandoned number stayed locked');

    owner.close();
    other.close();
  });

  test('an attached number is not given away by how long the answer takes', async () => {
    const owner = await register('recoverd');
    const attached = numberFor(41);
    assert.equal((await attach(owner, attached)).status, 204);

    // Matching status codes and bodies are worth nothing if a stopwatch
    // separates them. Sending only happens for a number the gateway knows, so
    // waiting for the send to finish before replying would make every attached
    // number answer a gateway round-trip slower than every unattached one —
    // readable from anywhere on the network, over as many numbers as you like.
    const timed = async (phoneNumber: string) => {
      const started = process.hrtime.bigint();
      const response = await start(phoneNumber);
      await response.arrayBuffer();
      return Number(process.hrtime.bigint() - started) / 1e6;
    };

    const known = await timed(attached);
    const unknown = await timed(numberFor(42));

    // Generous on purpose: this is not measuring a subtle difference, it is
    // checking that a whole SMS round trip does not sit inside the response.
    // Half the stand-in gateway's delay is far below what a real one costs and
    // far above the noise of a loopback request.
    assert.ok(
      known < SMS_GATEWAY_DELAY_MS / 2,
      `an attached number took ${known.toFixed(0)}ms, which means the reply waited for the SMS gateway`,
    );
    assert.ok(
      Math.abs(known - unknown) < SMS_GATEWAY_DELAY_MS / 2,
      `attached answered in ${known.toFixed(0)}ms and unattached in ${unknown.toFixed(0)}ms`,
    );

    owner.close();
  });

  test('recovery returns the handle, and every contact is told the keys changed', async () => {
    const owner = await register('recoverc');
    const friend = await register('recoverfriend');
    const number = numberFor(31);
    await attach(owner, number);

    // They were talking before the phone was lost.
    await owner.send(friend.username, 'before losing the phone');
    await friend.catchUp(() => {});
    const before = await friend.safetyNumber(owner.aci);

    // What the world saw before the phone was lost.
    const probe = await register('recoverprobe');
    const wasPublished = await publishedIdentityKey(probe, owner.aci);

    await start(number);
    const claim = recoveryBody(number, lastCode);
    const response = await postJson('/v1/recovery/complete', claim);
    assert.equal(response.status, 200);

    const recovered = (await response.json()) as { aci: string; usernameHash: string };
    assert.equal(
      recovered.usernameHash,
      b64(usernameHash(owner.username)),
      'the handle is the thing recovery hands back, as the hash the gateway holds',
    );
    assert.equal(recovered.aci, owner.aci, 'and the account it belonged to, so contacts still resolve');

    // The gateway never held the private key and cannot give it back, so the
    // recovered account is a different identity wearing the same name. That is
    // the whole security question of this feature: anyone who obtains the SIM
    // obtains the handle, so the change has to be visible to contacts rather
    // than smoothed over. Asserting on the published bundle is asserting on
    // exactly what every contact will fetch and compare against what it pinned.
    const nowPublished = await publishedIdentityKey(probe, owner.aci);
    assert.equal(nowPublished, claim['identityKey'], 'the recovering key is the one now published');
    assert.notEqual(
      nowPublished,
      wasPublished,
      'recovery left the old identity key in place, so no contact would ever be warned',
    );

    // And the friend is still holding the old one, which is what makes the
    // mismatch fire rather than the new key being silently adopted.
    assert.notEqual(before, '', 'the friend had pinned something to begin with');
    assert.equal(
      await friend.safetyNumber(owner.aci),
      before,
      'the pinned key moved on its own, which would defeat the warning entirely',
    );

    owner.close();
    friend.close();
    probe.close();
  });

  test('a code cannot be guessed through', async () => {
    const owner = await register('recoverb');
    const number = numberFor(21);
    await attach(owner, number);
    await start(number);

    // Six digits is a million, which is a lot to type and nothing to a script.
    // Every wrong answer spends one of a handful of attempts and then the code
    // is gone, so the number of guesses is the limit rather than the length.
    const wrong = recoveryBody(number, '000000');
    let refusedForCode = 0;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const response = await postJson('/v1/recovery/complete', wrong);
      if (response.status === 401) refusedForCode += 1;
      await response.arrayBuffer();
    }
    assert.ok(refusedForCode > 0, 'a wrong code must be refused');

    // And the real code no longer works either, because the guesses burned it.
    const genuine = await postJson('/v1/recovery/complete', recoveryBody(number, lastCode));
    assert.equal(genuine.status, 401, 'a code survived being guessed at');

    owner.close();
  });
});

describe('the vault refuses cost parameters it did not choose', () => {
  test('a tampered work factor is refused rather than honoured', async () => {
    const path = join(workdir, `kdf-${Date.now()}.db`);
    LocalStore.open(path, 'a passphrase').close();

    // scrypt sizes its working memory as 128 * N * r. The parameters live in
    // the vault so a database written under other settings still opens, which
    // means anyone who can write the file chooses how much memory the next
    // open must find. N = 2^24 asks for seventeen gigabytes; on a handset that
    // is the process being killed, for the price of editing one integer.
    const raw = new Database(path);
    raw.prepare('UPDATE vault SET kdf_n = ? WHERE id = 1').run(1 << 24);
    raw.close();

    assert.throws(
      () => LocalStore.open(path, 'a passphrase'),
      /KDF cost is out of range/,
      'an absurd work factor must be refused before scrypt is asked to honour it',
    );

    // The floor matters as much as the ceiling: a vault claiming N = 2 would
    // open under a key an offline search recovers immediately, and would keep
    // that setting.
    const weak = new Database(path);
    weak.prepare('UPDATE vault SET kdf_n = ? WHERE id = 1').run(2);
    weak.close();
    assert.throws(
      () => LocalStore.open(path, 'a passphrase'),
      /KDF cost is out of range/,
      'a trivially weak work factor must be refused too',
    );
  });
});

describe('a group is invisible to the gateway', () => {
  test('a removed member cannot read what comes next', async () => {
    const alice = await register('grpa');
    const bob = await register('grpb');
    const carol = await register('grpc');

    // Everyone learns everyone's bucket the only way there is — from a message.
    for (const peer of [bob, carol]) {
      await alice.send(peer.username, 'hello');
      await peer.catchUp(() => {});
      await peer.send(alice.username, 'hi');
    }
    await alice.catchUp(() => {});

    const group = await alice.createGroup('Ish', [bob.aci, carol.aci]);
    for (const peer of [bob, carol]) await peer.catchUp(() => {});
    assert.equal(bob.groups().length, 1, 'bob should see the group');
    assert.equal(carol.groups().length, 1, 'carol should see the group');

    await alice.updateGroupMembers(group.groupId, [bob.aci]);
    for (const peer of [bob, carol]) await peer.catchUp(() => {});
    assert.equal(carol.groups().length, 0, 'a removed member must lose the group');

    // The point of fanning out per member rather than sharing one group key:
    // removal takes effect on the very next message, with no key rotation to
    // remember and no window in which the removed member can still decrypt.
    await alice.sendToGroup(group.groupId, 'after the removal');
    const bobGot: string[] = [];
    const carolGot: string[] = [];
    await bob.catchUp((m) => { if (m.groupId === group.groupId) bobGot.push(m.body); });
    await carol.catchUp((m) => { if (m.groupId === group.groupId) carolGot.push(m.body); });

    assert.deepEqual(bobGot, ['after the removal'], 'a remaining member must still receive');
    assert.deepEqual(carolGot, [], 'a removed member must receive nothing');

    alice.close(); bob.close(); carol.close();
  });

  test('a removed member cannot be restored by replaying an old announcement', async () => {
    const alice = await register('rpa');
    const bob = await register('rpb');
    const mallory = await register('rpc');
    for (const [x, y] of [[alice, bob], [alice, mallory], [bob, mallory]] as const) {
      await x.send(y.username, 'hi'); await y.catchUp(() => {});
      await y.send(x.username, 'hi'); await x.catchUp(() => {});
    }

    const group = await alice.createGroup('Private', [bob.aci]);
    await bob.catchUp(() => {});
    assert.equal(bob.groups().length, 1);

    await alice.updateGroupMembers(group.groupId, []);
    await bob.catchUp(() => {});
    assert.equal(bob.groups().length, 0, 'bob should have been removed');

    // Removal deletes bob's copy of the group, which also deletes the revision
    // the replay check compares against. A tombstone has to survive it, or an
    // outsider can replay the original announcement — carrying a member list
    // of their own choosing — and bob starts sending group messages to them.
    const forged = { name: 'Pwned', members: [alice.aci, bob.aci, mallory.aci], event: 'update' as const, revision: 1 };
    await (mallory as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(bob.aci, 'forged', group.groupId, forged);
    await bob.catchUp(() => {});

    assert.equal(bob.groups().length, 0, 'a replayed announcement must not resurrect a group');

    alice.close(); bob.close(); mallory.close();
  });

  test('an announcement from someone outside the membership is refused', async () => {
    const alice = await register('oua');
    const bob = await register('oub');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    // Alice announces a group she is not a member of. Nonsense on its face,
    // and the shape a stranger would use to introduce a group built around a
    // list they chose.
    const control = { name: 'NotMine', members: [bob.aci], event: 'update' as const, revision: 1 };
    await (alice as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(bob.aci, 'x', b64(Buffer.alloc(16, 7)), control);
    await bob.catchUp(() => {});

    assert.equal(bob.groups().length, 0, 'an announcement excluding its own author must be refused');
    alice.close(); bob.close();
  });

  test('a member cannot freeze a group by claiming the highest possible revision', async () => {
    // Revisions order concurrent edits: highest seen wins, anything at or below
    // the stored value is stale. Unbounded, that rule is a weapon. A member
    // announces 2147483647; every client stores it; and no honest edit can ever
    // exceed it, because the next legitimate value is 2147483648 -- which does
    // not fit a 32-bit signed integer, reads back negative on Android, and is
    // dropped as malformed. The group is frozen at whatever roster the attacker
    // named, and the member who did it can never be removed.
    const alice = await register('freezea');
    const bob = await register('freezeb');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    const group = await alice.createGroup('Ours', [bob.aci]);
    await bob.catchUp(() => {});
    assert.equal(bob.groups().length, 1, 'expected the group under test to exist');

    // Bob is a real member, so every membership check passes. The only thing
    // standing between him and a permanent freeze is the ceiling.
    const control = {
      name: 'Ours',
      members: [alice.aci, bob.aci],
      event: 'update' as const,
      revision: 2147483647,
    };
    // It goes out -- an attacker runs their own client, so nothing stops them
    // emitting it. The defence has to be on the receiving side, and that is
    // what this asserts.
    await (bob as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(alice.aci, 'x', group.groupId, control);
    await alice.catchUp(() => {});

    const seen = alice.groups().find((g) => g.groupId === group.groupId);
    assert.ok(seen, 'the group must still be known');
    assert.ok(
      seen.revision <= MAX_GROUP_REVISION,
      `a revision past the ceiling must be ignored, stored revision is ${seen.revision}`,
    );

    // And the group is still editable, which is the property the freeze removed.
    const after = await alice.updateGroupMembers(group.groupId, [alice.aci]);
    assert.ok(after.revision < 1000, `the group must still take edits, revision is ${after.revision}`);

    alice.close(); bob.close();
  });

  test('a gateway cannot lose messages by returning them out of order', async () => {
    const alice = await register('ooa');
    const bob = await register('oob');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    for (let i = 0; i < 5; i++) await alice.send(bob.username, `m${i}`);

    // The order of this list is the gateway's choice and a hostile one is
    // inside the threat model. The cursor steps to each envelope's seq as it is
    // handled and skips anything at or below it, so an envelope taken early
    // that carries a high seq drops every envelope behind it — silently, and
    // permanently, because the cursor is persisted. Returning a genuine batch
    // in reverse lost four of these five.
    const inner = bob as unknown as {
      transport: { since(cursor: number): Promise<{ seq: number; content: string }[]> };
      enqueue(envelopes: unknown[], onMessage: (m: IncomingMessage) => void): Promise<void>;
    };
    const batch = await inner.transport.since(0);
    assert.ok(batch.length >= 5, 'expected the batch under test to be fetched');

    const got: string[] = [];
    await inner.enqueue([...batch].reverse(), (m) => { got.push(m.body); });

    assert.equal(
      got.filter((b) => /^m[0-4]$/.test(b)).length,
      5,
      'every message must survive a batch the gateway returned in reverse',
    );

    alice.close(); bob.close();
  });

  test('one envelope with a fabricated sequence number cannot silence an account', async () => {
    const alice = await register('csa');
    const bob = await register('csb');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    for (let i = 0; i < 3; i++) await alice.send(bob.username, `before${i}`);

    const inner = bob as unknown as {
      transport: { since(cursor: number): Promise<{ seq: number; content: string }[]> };
      enqueue(envelopes: unknown[], onMessage: (m: IncomingMessage) => void): Promise<void>;
    };

    // Sequence numbers are the gateway's and cannot be checked by the client.
    // One unopenable envelope claiming a very high seq used to move the cursor
    // past every message the account would ever receive — persisted, so it
    // survived a restart, and silent. The attack fired once and the damage was
    // permanent.
    const batch = await inner.transport.since(0);
    const poison = { seq: 999_999, content: b64(randomBytes(PADDED_ENVELOPE_BYTES)), arrivedAt: Date.now() };

    const during: string[] = [];
    await inner.enqueue([poison, ...batch], (m) => { during.push(m.body); });
    assert.equal(
      during.filter((b) => b.startsWith('before')).length,
      3,
      'genuine envelopes beside the poison must still be delivered',
    );

    // The attacker is gone. Everything from here is an honest gateway.
    await alice.send(bob.username, 'after the attack');
    const after: string[] = [];
    await bob.catchUp((m) => { after.push(m.body); });

    assert.ok(
      after.includes('after the attack'),
      'delivery must resume once the hostile response is over',
    );

    alice.close(); bob.close();
  });

  test('a group identifier outside the protocol shape is refused', async () => {
    const alice = await register('gia');
    const bob = await register('gib');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    // groupId is attacker-chosen and becomes a storage key on the recipient's
    // device. Left as a free-form string, one account could pick any length it
    // liked: at 2,000 characters a single message grew the victim's vault by
    // thirteen kilobytes, with nothing bounding the repeat.
    const send = (gid: string) => (alice as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(bob.aci, 'x', gid, { name: 'G', members: [bob.aci, alice.aci], event: 'update' as const, revision: 1 });

    for (const gid of ['A'.repeat(2000), 'ünïcödé', '../../etc/passwd', '', 'not base64!!']) {
      await send(gid);
    }
    await bob.catchUp(() => {});
    assert.equal(bob.groups().length, 0, 'a malformed group identifier must never be stored');

    // The well-formed shape still works, or the check has gone too far.
    const good = b64(randomBytes(16));
    await send(good);
    await bob.catchUp(() => {});
    assert.deepEqual(bob.groups().map((g) => g.groupId), [good], 'a real group identifier must still be accepted');

    alice.close(); bob.close();
  });

  test('one account cannot fill the device with groups', async () => {
    const alice = await register('cap1');
    const bob = await register('cap2');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    // Anybody who knows an account identifier can announce a group at it, which
    // is a documented limitation. Without a ceiling it is also a device-filling
    // attack from one account, since every unseen identifier is another entry.
    //
    // Driven at the apply step rather than over the wire: MAX_GROUPS + 8
    // submissions would empty the gateway's inbound bucket and fail the tests
    // that run after this one. The shape of the identifier is covered by the
    // test above; what is under test here is only the count.
    const apply = (gid: string) => (bob as unknown as {
      applyGroupUpdate(g: string, u: unknown, f: string): void;
    }).applyGroupUpdate(gid, { name: 'F', members: [bob.aci, alice.aci], event: 'update', revision: 1 }, alice.aci);

    for (let i = 0; i < MAX_GROUPS + 8; i++) apply(b64(randomBytes(16)));

    assert.equal(bob.groups().length, MAX_GROUPS, 'the number of groups a stranger can create must be bounded');

    // The ceiling must not freeze the groups already held.
    const held = bob.groups()[0];
    if (!held) throw new Error('expected groups at the cap');
    apply(held.groupId);
    (bob as unknown as {
      applyGroupUpdate(g: string, u: unknown, f: string): void;
    }).applyGroupUpdate(held.groupId, { name: 'Renamed', members: [bob.aci, alice.aci], event: 'update', revision: 99 }, alice.aci);
    assert.equal(bob.groups().find((g) => g.groupId === held.groupId)?.name, 'Renamed',
      'a group already held must still update after the cap is reached');
    alice.close(); bob.close();
  });

  test('a stranger cannot create a group by sending a leave', async () => {
    const alice = await register('lva');
    const bob = await register('lvb');
    await alice.send(bob.username, 'hi'); await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi'); await alice.catchUp(() => {});

    // The author-membership check is skipped for `leave`, because somebody
    // walking out is legitimately absent from the roster they send. Against a
    // groupId the recipient has never seen there is no existing state for the
    // revision or membership checks to test either, so `leave` was a way to
    // write an arbitrary group — name, roster, revision — onto a stranger's
    // device without breaking any cryptography. Alice has never been in this
    // group, and neither has bob.
    const control = { name: 'Pwned', members: [bob.aci], event: 'leave' as const, revision: 9999 };
    await (alice as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(bob.aci, 'x', b64(Buffer.alloc(16, 9)), control);
    await bob.catchUp(() => {});

    assert.equal(bob.groups().length, 0, 'a leave must never bring a group into existence');
    alice.close(); bob.close();
  });

  test('a leaving member cannot rename the group or rewrite its roster', async () => {
    const alice = await register('lwa');
    const bob = await register('lwb');
    const carol = await register('lwc');
    for (const [x, y] of [[alice, bob], [alice, carol], [bob, carol]] as const) {
      await x.send(y.username, 'hi'); await y.catchUp(() => {});
      await y.send(x.username, 'hi'); await x.catchUp(() => {});
    }

    const group = await alice.createGroup('Team', [bob.aci, carol.aci]);
    await bob.catchUp(() => {});
    assert.equal(bob.groups().length, 1);

    // Carol is a real member, so her leave is honoured — but a leave says only
    // that she is gone. The name and the remaining roster must come from bob's
    // own copy, not from her message, or walking out becomes a licence to
    // rewrite the group on the way through the door.
    const forged = { name: 'Renamed', members: [bob.aci, alice.aci, carol.aci], event: 'leave' as const, revision: group.revision + 1 };
    await (carol as unknown as {
      sendPayload(to: string, body: string, groupId: string, control: unknown): Promise<void>;
    }).sendPayload(bob.aci, 'bye', group.groupId, forged);
    await bob.catchUp(() => {});

    const after = bob.groups()[0];
    if (!after) throw new Error('bob should still hold the group after a leave');
    assert.equal(after.name, 'Team', 'a leave must not rename the group');
    assert.ok(!after.members.includes(carol.aci), 'the leaver must be removed');
    assert.deepEqual([...after.members].sort(), [alice.aci, bob.aci].sort(), 'the roster must come from our own copy');

    alice.close(); bob.close(); carol.close();
  });

  test('a real member leaving is still applied', async () => {
    const alice = await register('lra');
    const bob = await register('lrb');
    const carol = await register('lrc');
    for (const [x, y] of [[alice, bob], [alice, carol], [bob, carol]] as const) {
      await x.send(y.username, 'hi'); await y.catchUp(() => {});
      await y.send(x.username, 'hi'); await x.catchUp(() => {});
    }

    const group = await alice.createGroup('Walkers', [bob.aci, carol.aci]);
    await bob.catchUp(() => {});
    await carol.catchUp(() => {});
    assert.equal(carol.groups().length, 1, 'carol must hold the group before she can leave it');
    const before = bob.groups()[0];
    if (!before) throw new Error('bob should have received the group');
    assert.equal(before.members.length, 3, 'all three should be in it');

    // The guard above must not cost the ordinary case: a member who really
    // leaves has to disappear from everybody else's copy.
    await carol.leaveGroup(group.groupId);
    await bob.catchUp(() => {});

    const after = bob.groups()[0];
    if (!after) throw new Error('bob should still hold the group after carol leaves');
    assert.ok(!after.members.includes(carol.aci), 'a genuine leave must still remove the leaver');
    assert.equal(after.members.length, 2, 'the other two must remain');
    assert.equal(carol.groups().length, 0, 'the leaver forgets the group locally');

    alice.close(); bob.close(); carol.close();
  });

  test('the gateway stores nothing that identifies a group', async () => {
    const alice = await register('grpd');
    const bob = await register('grpe');
    await alice.send(bob.username, 'hello');
    await bob.catchUp(() => {});
    await bob.send(alice.username, 'hi');
    await alice.catchUp(() => {});

    const group = await alice.createGroup('Maxfiy', [bob.aci]);
    await bob.catchUp(() => {});
    await alice.sendToGroup(group.groupId, 'group secret');
    await bob.catchUp(() => {});

    // The schema is the claim: there is no column a subpoena could name.
    const raw = new Database(join(workdir, 'relay.db'), { readonly: true });
    const columns = raw.prepare('PRAGMA table_info(envelopes)').all() as { name: string }[];
    raw.close();
    assert.ok(
      !columns.some((c) => /group|recipient|sender/i.test(c.name)),
      `envelopes must not carry group or party columns, got: ${columns.map((c) => c.name).join(',')}`,
    );

    // And the identifier the members agreed on must not be recoverable from
    // the file, in either the encoded or the raw form.
    const bytes = readFileSync(join(workdir, 'relay.db'));
    assert.ok(!bytes.includes(Buffer.from(group.groupId, 'utf8')), 'group id leaked in encoded form');
    assert.ok(!bytes.includes(Buffer.from(unb64(group.groupId))), 'group id leaked in raw form');
    assert.ok(!bytes.includes(Buffer.from('group secret', 'utf8')), 'group plaintext leaked');

    alice.close(); bob.close();
  });
});

describe('an oblivious submission is cheap to refuse', () => {
  test('the sealed size the gateway expects is the size sealing produces', () => {
    // Hardcoding a length is only safe while something checks it. If
    // libsignal's HPKE overhead ever changes, this fails here rather than in
    // the field, where the gateway would refuse every real submission before
    // trying to open it.
    const recipient = PrivateKey.generate().getPublicKey();
    const sealed = recipient.seal(
      new Uint8Array(OBLIVIOUS_REQUEST_BYTES),
      Buffer.from(OBLIVIOUS_INFO, 'utf8'),
      new Uint8Array(0),
    );
    assert.equal(sealed.length, OBLIVIOUS_SEALED_BYTES);
  });

  test('a wrong-sized body is refused without any key agreement', async () => {
    for (const size of [1, 64, OBLIVIOUS_SEALED_BYTES - 1, OBLIVIOUS_SEALED_BYTES + 1]) {
      const response = await fetch(`${server.url}/v1/oblivious`, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: new Uint8Array(size),
      });
      await response.arrayBuffer();
      assert.equal(response.status, 400, `a ${size}-byte body must be refused`);
    }
  });
});

describe('medium-term keys are actually medium-term', () => {
  test('rotation replaces the published pair and keeps the previous one usable', async () => {
    const owner = await register('rotator');
    const early = await register('earlybird');
    const late = await register('latecomer');

    const bundleFor = async (client: MillygramClient, target: string) => {
      const token = await (client as unknown as { transport: { accessToken(): Promise<string> } })
        .transport.accessToken();
      const response = await fetch(`${server.url}/v1/keys/${target}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      return (await response.json()) as {
        signedPreKey: { keyId: number };
        kyberPreKey: { keyId: number };
      };
    };

    const before = await bundleFor(early, owner.aci);

    // Someone fetches a bundle and starts writing, but their message has not
    // arrived yet when the rotation happens.
    await early.send(owner.username, 'sent against the old signed prekey');

    // Far enough in the future that the pair is due for replacement.
    await owner.rotatePreKeys(Date.now() + PREKEY_ROTATION_MS + 1);

    const after = await bundleFor(late, owner.aci);
    assert.notEqual(after.signedPreKey.keyId, before.signedPreKey.keyId, 'the signed prekey must change');
    assert.notEqual(after.kyberPreKey.keyId, before.kyberPreKey.keyId, 'the kyber prekey must change');

    // The in-flight message names the key that has just been replaced. Losing
    // it here would be silent: an envelope that will not open is exactly what
    // every other member of the bucket sees.
    const inbox: IncomingMessage[] = [];
    await owner.catchUp((message) => {
      inbox.push(message);
    });
    assert.deepEqual(
      inbox.map((m) => m.body),
      ['sent against the old signed prekey'],
      'a session opened just before rotation must still be readable',
    );

    // And the newly published pair works for someone arriving after it.
    await late.send(owner.username, 'sent against the new signed prekey');
    const second: IncomingMessage[] = [];
    await owner.catchUp((message) => {
      second.push(message);
    });
    assert.deepEqual(second.map((m) => m.body), ['sent against the new signed prekey']);

    owner.close();
    early.close();
    late.close();
  });
});

describe('limiter state cannot be grown by a stranger', () => {
  test('a bundle request for an account that does not exist charges nothing', async () => {
    const caller = await register('ghostcaller');
    const token = await (caller as unknown as { transport: { accessToken(): Promise<string> } })
      .transport.accessToken();

    // The same non-existent target, more times than the per-caller allowance.
    // The limiters keep a bucket per key and one key is a caller/target pair,
    // so charging before the lookup meant every request for a made-up target
    // created buckets that never throttled — a fresh key starts full — and
    // were held for the best part of an hour. Unbounded memory for the cost of
    // a 404.
    const ghost = '00000000-0000-4000-8000-0000000000ff';
    const seen = new Set<number>();
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const response = await fetch(`${server.url}/v1/keys/${ghost}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      seen.add(response.status);
      await response.arrayBuffer();
    }

    assert.deepEqual(
      [...seen],
      [404],
      'an unknown target must always be a plain 404, never a throttle, because nothing was charged',
    );

    caller.close();
  });
});

describe('malformed input is refused, not crashed on', () => {
  // "AAAAA" is five base64url characters, which no byte string encodes to.
  // "!!!!" is the right length and the wrong alphabet. Both reach the decoder
  // through a field the schema is supposed to have already validated.
  const nonsense = ['!!!!', 'AAAAA'];

  test('a bad base64 field is a bad request, on every route that takes one', async () => {
    for (const bad of nonsense) {
      const submitted = await submit({ bucketId: 0, content: bad, nonce: 1 });
      assert.equal(submitted.status, 400, `submission with ${bad} must be refused cleanly`);

      const { body } = buildRegistration(unique('badb64').username);
      const registered = await postJson('/v1/accounts', { ...body, identityKey: bad });
      assert.equal(registered.status, 400, `registration with ${bad} must be refused cleanly`);

      const authed = await postJson('/v1/accounts/auth', {
        aci: '00000000-0000-4000-8000-000000000000',
        deviceId: 1,
        nonce: bad,
        signature: 'AA',
      });
      assert.equal(authed.status, 400, `auth with ${bad} must be refused cleanly`);
    }
  });

  test('a self-reported environment signal is accepted and never gates by default', async () => {
    // Registered raw so the test holds the identity and can sign auth itself,
    // then attach an environment field the real client would send.
    const { identity, body: regBody } = buildRegistration(unique('envsignal').username);
    const created = await postJson('/v1/accounts', regBody);
    assert.equal(created.status, 201);
    const aci = ((await created.json()) as { aci: string }).aci;

    const authWith = async (environment?: string): Promise<number> => {
      const challenge = (await (
        await fetch(`${server.url}/v1/accounts/challenge?aci=${aci}`)
      ).json()) as { nonce: string };
      const body: Record<string, unknown> = {
        aci,
        deviceId: 1,
        nonce: challenge.nonce,
        signature: b64(identity.privateKey.sign(authSigningPayload(aci, 1, unb64(challenge.nonce)))),
      };
      if (environment !== undefined) body.environment = environment;
      return (await postJson('/v1/accounts/auth', body)).status;
    };

    // The whole point of the default: a device that honestly admits it is
    // rooted still gets in, because the checks behind that word are defeatable
    // and refusing on them only ever turns away the honest client. A signal to
    // record, not a gate.
    assert.equal(await authWith('clean'), 200);
    assert.equal(await authWith('root,hook,emulator'), 200, 'the default must not gate on the signal');
    // And an absent field is fine — older clients that never learned to send it.
    assert.equal(await authWith(undefined), 200);
    // A field longer than the schema allows is a bad request, not a crash.
    assert.equal(await authWith('x'.repeat(200)), 400);
  });

  test('a refusal carries no internal detail', async () => {
    const response = await submit({ bucketId: 0, content: '!!!!', nonce: 1 });
    const text = await response.text();

    // The decoder's own message named the failure mode and reached the wire as
    // a 500. Validation failures say invalid_request and nothing else.
    assert.ok(!/canonical|base64url|stack|at Object/i.test(text), `leaked internals: ${text}`);
  });
});

describe('rate limiting is not keyed on the caller address', () => {
  /** One full challenge/response round for an account. */
  const authenticate = async (aci: string, identity: IdentityKeyPair): Promise<number> => {
    const challenge = (await (
      await fetch(`${server.url}/v1/accounts/challenge?aci=${aci}`)
    ).json()) as { nonce: string };
    const response = await postJson('/v1/accounts/auth', {
      aci,
      deviceId: 1,
      nonce: challenge.nonce,
      signature: b64(identity.privateKey.sign(authSigningPayload(aci, 1, unb64(challenge.nonce)))),
    });
    return response.status;
  };

  test('many accounts can register from one address', async () => {
    // Every request in this suite comes from the same address, which is the
    // situation of an entire Uzbek carrier behind one NAT. Under the old
    // per-address limit the sixth of these would have been refused.
    for (let n = 0; n < 12; n += 1) {
      const { body } = buildRegistration(unique(`nat${n}`).username);
      const response = await postJson('/v1/accounts', body);
      assert.equal(response.status, 201, `registration ${n} from a shared address must succeed`);
    }
  });

  test('a registration without work is refused, and told what it costs', async () => {
    const { body } = buildRegistration(unique('nowork').username);
    const response = await postJson('/v1/accounts', { ...body, workNonce: 0 });

    assert.equal(response.status, 400);
    const refusal = (await response.json()) as { error: string; difficulty: number };
    assert.equal(refusal.error, 'work_required');
    assert.equal(
      refusal.difficulty,
      TEST_REGISTRATION_POW,
      'the refusal must say what to pay, so a client can pay more without a new build',
    );
  });

  test('one account exhausting auth does not lock out another', async () => {
    const noisy = buildRegistration(unique('noisy').username);
    const quiet = buildRegistration(unique('quiet').username);
    const noisyAci = ((await (await postJson('/v1/accounts', noisy.body)).json()) as { aci: string }).aci;
    const quietAci = ((await (await postJson('/v1/accounts', quiet.body)).json()) as { aci: string }).aci;

    // Spend the noisy account's whole per-account allowance.
    let refused = 0;
    for (let n = 0; n < 30; n += 1) {
      if ((await authenticate(noisyAci, noisy.identity)) === 429) refused += 1;
    }
    assert.ok(refused > 0, 'a single account must still be limited');

    // The quiet account shares the address and nothing else.
    assert.equal(
      await authenticate(quietAci, quiet.identity),
      200,
      'an account must not be locked out by what a neighbour on its address did',
    );
  });
});

describe('the relay rejects forged credentials', () => {
  test('a registration signature that does not cover the handle is refused', async () => {
    const { body } = buildRegistration('honest_user');
    // The signature is genuine; it was simply made over a different handle. The
    // payload commits to the hash, so swapping the hash is precisely what a
    // name-stealing registration would have to do — and the proof is swapped
    // with it, so what refuses this is the signature and nothing else.
    const impostor = usernameCandidates('impostor_user')[0]!;
    const response = await postJson(
      '/v1/accounts',
      reworked({
        ...body,
        usernameHash: b64(usernameHash(impostor)),
        usernameProof: b64(usernameProof(impostor)),
      }),
    );

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'invalid_signature');
  });

  test('a prekey signed by a different identity is refused', async () => {
    const { body } = buildRegistration('prekey_victim');
    const attacker = IdentityKeyPair.generate();
    const foreignKey = PrivateKey.generate().getPublicKey();

    const response = await postJson(
      '/v1/accounts',
      reworked({
        ...body,
        signedPreKey: {
          keyId: 1,
          publicKey: b64(foreignKey.serialize()),
          signature: b64(attacker.privateKey.sign(foreignKey.serialize())),
        },
      }),
    );

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

/**
 * Retention is a timer, and a timer is not a ceiling.
 *
 * Envelopes and the digests that stop them being replayed were bounded only by
 * the fourteen-day sweep, so disk grew linearly with whatever CPU an attacker
 * cared to spend: roughly 65 GB of envelopes and 0.8 GB of digests per attacker
 * core at the steady state, with nothing underneath. These tests pin the two
 * ceilings that now sit under the timer, and — the harder half — pin that the
 * cheaper of the two was not bought by reopening free replay.
 */
describe('storage is bounded by more than the retention window', () => {
  /** A gateway of its own with the ceilings turned down far enough to reach. */
  const cappedGateway = (label: string, overrides: Partial<ServerConfig>): Promise<RunningServer> => {
    counter += 1;
    return startServer({
      host: '127.0.0.1',
      port: 0,
      databasePath: join(workdir, `${label}-${counter}.db`),
      rateLimits: testRateLimits,
      powDifficulty: TEST_POW_DIFFICULTY,
      registrationPowDifficulty: TEST_REGISTRATION_POW,
      ...overrides,
    });
  };

  /** Registers one account and reports the bucket it landed in. */
  const newBucket = async (gateway: RunningServer, label: string): Promise<number> => {
    const account = buildRegistration(unique(label).username);
    const response = await fetch(`${gateway.url}/v1/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(account.body),
    });
    assert.equal(response.status, 201);
    return ((await response.json()) as { bucketId: number }).bucketId;
  };

  interface Submission {
    bucketId: number;
    content: string;
    nonce: number;
  }

  /** A fresh, unique, fully paid-for submission. */
  const solved = (bucketId: number): Submission => {
    const content = randomBytes(PADDED_ENVELOPE_BYTES);
    return { bucketId, content: b64(content), nonce: solveProofOfWork(bucketId, content, TEST_POW_DIFFICULTY) };
  };

  const offer = async (
    gateway: RunningServer,
    body: Submission,
  ): Promise<{ status: number; error?: string }> => {
    const response = await fetch(`${gateway.url}/v1/messages`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let error: string | undefined;
    try {
      const parsed: unknown = text ? JSON.parse(text) : null;
      if (typeof parsed === 'object' && parsed !== null && 'error' in parsed) {
        error = String((parsed as { error: unknown }).error);
      }
    } catch {
      // A 202 answers with an empty body, which is not JSON and does not need to be.
    }
    return error === undefined ? { status: response.status } : { status: response.status, error };
  };

  test('a bucket at its ceiling refuses new envelopes and keeps the ones it holds', async () => {
    const gateway = await cappedGateway('bucketceiling', {
      maxEnvelopesPerBucket: 3,
      maxEnvelopesTotal: 1_000_000,
    });

    try {
      const bucketId = await newBucket(gateway, 'ceilingvictim');

      const stored: string[] = [];
      for (let i = 0; i < 3; i += 1) {
        const body = solved(bucketId);
        assert.equal((await offer(gateway, body)).status, 202, `envelope ${i + 1} is inside the ceiling`);
        stored.push(body.content);
      }

      const refused = await offer(gateway, solved(bucketId));
      assert.equal(refused.status, 429, 'a bucket at its ceiling must refuse a new envelope');
      assert.equal(refused.error, 'bucket_full', 'and say which ceiling it was');

      // The requirement the whole ceiling lives under. Nothing already accepted
      // is thrown away to make room for what arrives next: the relay does not
      // know which of a bucket's members an envelope belongs to, or whether
      // they have collected it, so evicting one is dropping a message that
      // nobody is ever told went missing. Refusing costs a sender a message
      // they are told about and can send again, and it is the only one of the
      // two that anybody finds out about.
      assert.deepEqual(
        gateway.store.since(bucketId, 0).map((row) => b64(row.content)),
        stored,
        'the backlog must be exactly what was accepted, in order, with nothing evicted',
      );
    } finally {
      await gateway.close();
    }
  });

  test('a full relay refuses the bucket that filled it, not the quiet one', async () => {
    // One account per bucket, so two accounts are two buckets and the share
    // arithmetic is visible in four envelopes rather than in four million.
    const gateway = await cappedGateway('relayceiling', {
      bucketSize: 1,
      maxEnvelopesPerBucket: 1_000,
      maxEnvelopesTotal: 4,
    });

    try {
      const flooded = await newBucket(gateway, 'floodbucket');
      const quiet = await newBucket(gateway, 'quietbucket');
      assert.notEqual(flooded, quiet, 'the two accounts must land in different buckets');

      for (let i = 0; i < 4; i += 1) {
        assert.equal((await offer(gateway, solved(flooded))).status, 202, `envelope ${i + 1} fits`);
      }

      // The relay's entire ceiling is four envelopes and one bucket is holding
      // all four, which is more than its equal share. It is refused.
      const refused = await offer(gateway, solved(flooded));
      assert.equal(refused.status, 429, 'a relay at its ceiling must refuse the bucket filling it');
      assert.equal(refused.error, 'relay_full');

      // And the point of measuring the share rather than refusing everybody: a
      // bucket that has sent nothing is under its share, so filling a disk is
      // not a way to stop delivery for every other user of the gateway.
      assert.equal(
        (await offer(gateway, solved(quiet))).status,
        202,
        'a bucket under its share must still receive while the relay is full',
      );
    } finally {
      await gateway.close();
    }
  });

  test('a throttled submission leaves no replay row, and a replay still spends nothing', async () => {
    // Two tokens and no refill, so the bucket empties and stays empty. The
    // escalating price is switched off here because what is under test is the
    // order of the checks, not the ramp -- with it on, a drained bucket answers
    // 400 and asks for more work, and these submissions would never reach the
    // limiter they are meant to be refused by.
    const gateway = await cappedGateway('digestorder', {
      rateLimits: { ...testRateLimits, inbound: { capacity: 2, refillPerSecond: 0 } },
      inboundPowEscalationMax: 0,
    });

    try {
      const bucketId = await newBucket(gateway, 'digestvictim');

      const accepted: Submission[] = [];
      for (let i = 0; i < 2; i += 1) {
        const body = solved(bucketId);
        assert.equal((await offer(gateway, body)).status, 202, `envelope ${i + 1} is inside the budget`);
        accepted.push(body);
      }

      // Every one of these carries real, unique, valid work and is refused by
      // the inbound limiter. It is exactly the traffic a flooder produces, six
      // a second a core, for as long as they care to.
      for (let i = 0; i < 6; i += 1) {
        const refused = await offer(gateway, solved(bucketId));
        assert.equal(refused.status, 429, 'the inbound limit must still refuse');
        assert.equal(refused.error, 'slow_down');
      }

      // The replay table used to grow at the full work rate whatever the
      // limiter said -- measured at 200 rows for 60 delivered envelopes, and
      // unbounded above that, because the row was written before the limiter
      // was asked. It may now only hold what was actually stored, which means
      // it can never outgrow the table it protects.
      assert.equal(
        gateway.store.dumpTable('submission_digests').length,
        accepted.length,
        'a submission the limiter refused must not leave a replay row behind',
      );

      // The half that must not be traded away to get it. Simply swapping the
      // two lines would answer this 429 -- having already taken a token for a
      // copy of work somebody else paid for. Whoever captured one envelope
      // could then hold a bucket empty forever at no cost, which is the
      // expensive attack this gateway prices in proof of work, made free.
      const replayed = await offer(gateway, accepted[0]!);
      assert.equal(replayed.status, 409, 'a replay must be refused as a replay, not throttled');
      assert.equal(replayed.error, 'duplicate_submission');
    } finally {
      await gateway.close();
    }
  });
});

/**
 * The same rule the submission path already follows, applied to every other
 * unauthenticated route: validate the request and make it prove its work first,
 * charge the shared bucket last.
 *
 * A global ceiling is a circuit breaker on things that actually happened. Spent
 * at the top of a route it becomes the opposite — a lever anyone can pull, for
 * the price of a few hundred bytes of rubbish, to close signups, login or
 * account recovery for every user of the gateway at once. These tests exist to
 * fail if a limiter ever drifts back above the checks it is supposed to sit
 * beneath, which is a change that looks harmless in a diff.
 */
describe('an unpaid request cannot spend the budget of a paid one', () => {
  /**
   * A gateway of its own, with the ceiling under test turned down to a handful
   * of tokens.
   *
   * These tests work by emptying buckets, which is not something to do to the
   * relay every other test in this file shares. Small capacities also make the
   * point in forty requests rather than four thousand: what is asserted here is
   * an ordering, and an ordering does not care how deep the bucket is.
   */
  const narrowGateway = (label: string, rateLimits: RateLimits): Promise<RunningServer> => {
    counter += 1;
    return startServer({
      host: '127.0.0.1',
      port: 0,
      databasePath: join(workdir, `${label}-${counter}.db`),
      rateLimits,
      powDifficulty: TEST_POW_DIFFICULTY,
      registrationPowDifficulty: TEST_REGISTRATION_POW,
    });
  };

  test('a bucket being drained charges more for the next submission', async () => {
    // Delivery is per-bucket and submission is anonymous, so there is no sender
    // to rate-limit: the inbound budget is shared by all sixteen members of a
    // bucket and one flooder can spend the lot, after which nobody can message
    // any of them. Bucket ids are sequential and the directory hands them out,
    // so choosing a victim is free. Measured against the real gateway, holding
    // one bucket empty cost 0.78% of a core.
    //
    // It cannot be fixed by refusing harder -- refusing is the harm. What is
    // left is to make the budget set a price: as it drains, the work each
    // submission must carry climbs, so the flooder pays 2^escalation to keep
    // sixteen people cut off. No refill here, so the ramp is deterministic.
    const gateway = await narrowGateway('inboundprice', {
      ...testRateLimits,
      inbound: { capacity: 4, refillPerSecond: 0 },
    });

    try {
    const account = buildRegistration(unique('pricevictim').username);
    const registered = await post(gateway, '/v1/accounts', account.body);
    assert.equal(registered.status, 201);
    const { bucketId } = (await registered.json()) as { bucketId: number };

    const offer = async (difficulty: number) => {
      // Work worth exactly what was asked for, and not a bit more.
      //
      // A solver returns the first nonce it finds, which clears the requested
      // difficulty and, half the time, one bit above it; three bits above about
      // one time in eight. A nonce worth three extra bits satisfies an
      // escalated price it never paid, so the assertions below about a
      // submission being refused held roughly seven runs in eight and failed
      // the other one - a test that fails 13% of the time is not a test.
      // Drawing again until the work is exact makes this about the price.
      let content = randomBytes(PADDED_ENVELOPE_BYTES);
      let nonce = solveProofOfWork(bucketId, content, difficulty);
      while (verifyProofOfWork(bucketId, content, nonce, difficulty + 1)) {
        content = randomBytes(PADDED_ENVELOPE_BYTES);
        nonce = solveProofOfWork(bucketId, content, difficulty);
      }
      const response = await fetch(`${gateway.url}/v1/messages`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ bucketId, content: b64(content), nonce }),
      });
      const body = response.status === 400 ? ((await response.json()) as { difficulty?: number }) : null;
      await response.arrayBuffer().catch(() => undefined);
      return { status: response.status, asked: body?.difficulty };
    };

    // While the budget is more than half there, ordinary traffic pays nothing
    // extra. This is the part that must not regress: the price is for pressure,
    // not for sending.
    for (let i = 0; i < 3; i += 1) {
      assert.equal((await offer(TEST_POW_DIFFICULTY)).status, 202, `submission ${i + 1} must be free of surcharge`);
    }

    // Past halfway the base price is no longer enough, and the refusal says so.
    const underpaid = await offer(TEST_POW_DIFFICULTY);
    assert.equal(underpaid.status, 400);
    assert.ok(
      underpaid.asked !== undefined && underpaid.asked > TEST_POW_DIFFICULTY,
      `a drained bucket must quote a higher difficulty, got ${underpaid.asked}`,
    );

    // And quoting it is not a way of saying no: paying it gets the message in.
    assert.equal((await offer(underpaid.asked!)).status, 202, 'the quoted price must actually buy delivery');

    // Empty now. This is what the flooder pays on every message to hold the
    // bucket down -- the whole cost of the attack, multiplied.
    const drained = await offer(TEST_POW_DIFFICULTY);
    assert.equal(drained.status, 400);
    assert.equal(
      drained.asked,
      TEST_POW_DIFFICULTY + DEFAULT_INBOUND_POW_ESCALATION,
      'an empty bucket must charge the full escalation',
    );
    } finally {
      await gateway.close();
    }
  });

  const post = (gateway: RunningServer, path: string, body: unknown): Promise<Response> =>
    fetch(`${gateway.url}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

  /** Bodies that cannot survive a schema check, whatever route they are aimed at. */
  const junk: unknown[] = [
    {},
    { phoneNumber: 42 },
    { aci: 'not-a-uuid', deviceId: 1 },
    'a string where an object belongs',
    [],
  ];

  /** Refilling this slowly means a drained bucket stays drained for the test. */
  const drainedForAnHour = (capacity: number) => ({ capacity, refillPerSecond: 1 / 3600 });

  test('a flood of malformed starts does not close recovery for whoever lost their phone', async () => {
    const gateway = await narrowGateway('recoveryflood', {
      ...testRateLimits,
      recovery: drainedForAnHour(4),
    });

    // Four tokens in the bucket, forty requests, not one of which parses. While
    // this limiter was the first statement of the route, that alone denied
    // recovery to every user of the gateway for the next hour, and the sender
    // paid nothing for it.
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await post(gateway, '/v1/recovery/start', junk[attempt % junk.length]);
      assert.equal(response.status, 400, 'a body that does not parse must be refused on its merits');
      await response.arrayBuffer();
    }

    const honest = await post(gateway, '/v1/recovery/start', { phoneNumber: '+998901234567' });
    assert.equal(
      honest.status,
      202,
      'a well-formed recovery must survive a flood of malformed ones',
    );
    await honest.arrayBuffer();

    await gateway.close();
  });

  test('a flood of malformed auth posts does not stop anybody logging in', async () => {
    const gateway = await narrowGateway('authflood', {
      ...testRateLimits,
      auth: drainedForAnHour(4),
    });

    const account = buildRegistration(unique('floodvictim').username);
    const registered = await post(gateway, '/v1/accounts', account.body);
    assert.equal(registered.status, 201);
    const { aci } = (await registered.json()) as { aci: string };

    for (let attempt = 0; attempt < 20; attempt += 1) {
      const response = await post(gateway, '/v1/accounts/auth', junk[attempt % junk.length]);
      assert.equal(response.status, 400);
      await response.arrayBuffer();
    }

    // And the shaped-but-worthless case, which is the one that matters: a body
    // the schema accepts, naming a nonce this gateway never issued. It is
    // refused before any public-key work happens, so it has bought nothing and
    // must therefore have spent nothing.
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const response = await post(gateway, '/v1/accounts/auth', {
        aci,
        deviceId: 1,
        nonce: b64(randomBytes(32)),
        signature: b64(randomBytes(64)),
      });
      assert.equal(response.status, 401, 'an unknown nonce must be refused, not throttled');
      await response.arrayBuffer();
    }

    // Challenges used to come out of the same bucket the flood above emptied,
    // so this was the shape of the denial: no nonce, and therefore no way for
    // anyone to log in at all.
    const challenge = await fetch(`${gateway.url}/v1/accounts/challenge?aci=${aci}`);
    assert.equal(challenge.status, 200, 'a challenge must still be issued after a flood at auth');
    const { nonce } = (await challenge.json()) as { nonce: string };

    const answered = await post(gateway, '/v1/accounts/auth', {
      aci,
      deviceId: 1,
      nonce,
      signature: b64(account.identity.privateKey.sign(authSigningPayload(aci, 1, unb64(nonce)))),
    });
    assert.equal(answered.status, 200, 'an honest login must survive a flood of worthless ones');
    await answered.arrayBuffer();

    await gateway.close();
  });

  test('emptying the recovery-start budget does not also close recovery-complete', async () => {
    const gateway = await narrowGateway('recoverysplit', {
      ...testRateLimits,
      recovery: drainedForAnHour(3),
    });

    // Well-formed this time, each for a different number so it is the gateway's
    // ceiling that runs out rather than any one number's allowance. Somebody
    // doing this is spending nothing and cannot be stopped from doing it.
    let refused = 0;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const response = await post(gateway, '/v1/recovery/start', {
        phoneNumber: `+99890200${String(1000 + attempt).slice(0, 4)}`,
      });
      if (response.status === 429) refused += 1;
      await response.arrayBuffer();
    }
    assert.ok(refused > 0, 'the start ceiling must actually have been reached');

    // The two routes shared one bucket, so the flood above used to switch off
    // the half that people only reach once a code has already been sent to
    // them. A wrong code is the right answer here; a throttle is not.
    const completed = await post(
      gateway,
      '/v1/recovery/complete',
      recoveryBody('+998903334444', '000000'),
    );
    assert.notEqual(
      completed.status,
      429,
      'completing a recovery must not be rationed out of the start budget',
    );
    assert.equal(completed.status, 401, 'and it must still be refused on the code it carries');
    await completed.arrayBuffer();

    await gateway.close();
  });

  test('a flood of unpaid registrations does not close signups', async () => {
    const gateway = await narrowGateway('registrationflood', {
      ...testRateLimits,
      registration: drainedForAnHour(4),
    });

    // A registration that is otherwise perfect and has simply not paid for
    // itself. The nonce is searched for rather than guessed, so the refusal is
    // certain instead of merely likely.
    const { body } = buildRegistration(unique('freeloader').username);
    const { signature, workNonce, ...unsigned } = body;
    let badNonce = 0;
    while (verifyRegistrationWork(registrationSigningPayload(unsigned), badNonce, TEST_REGISTRATION_POW)) {
      badNonce += 1;
    }
    const unpaid = { ...body, workNonce: badNonce };

    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await post(
        gateway,
        '/v1/accounts',
        attempt % 2 === 0 ? junk[attempt % junk.length] : unpaid,
      );
      assert.equal(response.status, 400, 'a registration that paid nothing must be refused, not rationed');
      await response.arrayBuffer();
    }

    // The proof of work is what makes flooding this route expensive. Charging
    // the gateway's signup ceiling for requests that never paid it meant anyone
    // could close registration for the whole country for free.
    const honest = await post(gateway, '/v1/accounts', buildRegistration(unique('latecomer').username).body);
    assert.equal(honest.status, 201, 'a registration that paid its work must survive a flood of ones that did not');
    await honest.arrayBuffer();

    await gateway.close();
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

    // The handle, not the nickname it was registered under: the gateway chose
    // four digits that this test cannot predict, and a bare nickname is no
    // longer a name the directory will resolve.
    await alisher.send(nodira.username, 'a private message');

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

  test('the length declared inside an envelope does not track the message', async () => {
    // The envelope being a constant 8192 bytes was never the whole story. It
    // carries a cleartext uint32 saying how much of itself is real, and that
    // number tracked the body to within about ten bytes: 2224 for a one-byte
    // message, 6225 for a four-thousand-byte one. The gateway reads it, and so
    // does every one of the ~16 accounts sharing the bucket, because all of
    // them download every envelope. That is enough to tell a short code from a
    // paragraph, to pair a message with its reply by length, and to spot the
    // same body fanned out to a group.
    const sender = await register('declsender');
    const receiver = await register('declreceiver');
    const cursor = bucketCursor(receiver.bucketId);

    await sender.send(receiver.username, 'setting up the session');
    await sender.send(receiver.username, 'ha');
    await sender.send(receiver.username, 'x'.repeat(3000));

    const queued = server.store.since(receiver.bucketId, cursor);
    assert.equal(queued.length, 3);

    const declared = queued.map((row) => Buffer.from(row.content).readUInt32BE(0));
    assert.equal(
      new Set(declared).size,
      1,
      `every envelope must declare the same length whatever it carries, got ${declared.join(', ')}`,
    );

    // And that one length is the padded payload plus whatever libsignal adds,
    // which has to leave room inside the envelope rather than only just fit.
    assert.ok(
      declared[0]! > PADDED_PAYLOAD_BYTES && declared[0]! <= PADDED_ENVELOPE_BYTES - 4,
      `declared ${declared[0]} must sit between the padded payload and the envelope`,
    );

    sender.close();
    receiver.close();
  });

  test('a message too large to pad is refused before the ratchet advances', async () => {
    // A body of 4096 quote characters is legal — the limit counts UTF-8 bytes,
    // and it is exactly 4096 of them — but JSON escaping doubles it to 8267,
    // which no envelope can hold. This used to surface as a RangeError thrown
    // from pad(), after sealedSenderEncryptMessage had already advanced the
    // ratchet and spent a message key on a send that could never leave.
    const sender = await register('overlong');
    const receiver = await register('overlongpeer');

    await assert.rejects(
      () => sender.send(receiver.username, '"'.repeat(MAX_PLAINTEXT_BYTES)),
      /does not fit one envelope/,
      'an unsendable payload must be refused by name, not by RangeError from the padding',
    );

    // The session is still usable: nothing was consumed on the way out.
    await sender.send(receiver.username, 'still works');

    sender.close();
    receiver.close();
  });

  test('padding round-trips and produces a constant envelope size', () => {
    // pad() still writes the payload's real length into the first four bytes,
    // outside the encryption, and this test still says so. What changed is what
    // that number is now capable of revealing: the payload handed to pad() is
    // padded to a constant before it is sealed, so the declared length no longer
    // varies with the message. The test below this one is the one that holds
    // that property; this one covers pad() itself, which is unchanged.
    const short = Buffer.from('ha', 'utf8');
    const long = Buffer.from('x'.repeat(3000), 'utf8');

    assert.equal(pad(short).length, PADDED_ENVELOPE_BYTES);
    assert.equal(pad(long).length, PADDED_ENVELOPE_BYTES);
    assert.deepEqual(Buffer.from(unpad(pad(short))), short);
    assert.deepEqual(Buffer.from(unpad(pad(long))), long);

    // And the property the old name implied, stated as the fact it is: the
    // declared length is readable from the envelope without any key.
    assert.equal(Buffer.from(pad(short)).readUInt32BE(0), short.length);
    assert.equal(Buffer.from(pad(long)).readUInt32BE(0), long.length);
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
    const flagged: string[] = [];
    alice.onIdentityMismatch = (senderAci) => flagged.push(senderAci);

    await bob.send(alice.aci, 'the real Bob, writing back');

    const alicesInbox: IncomingMessage[] = [];
    await alice.catchUp((message) => {
      alicesInbox.push(message);
    });

    assert.equal(alicesInbox.length, 0, 'a message under an unpinned identity must not be delivered');
    assert.equal(flagged.length, 1, 'the substitution must be reported, not swallowed as bucket noise');
    assert.equal(
      flagged[0],
      bob.aci,
      'the report must name the contact, or the caller cannot mark the conversation',
    );

    // The warning has to lead somewhere. Until the old key is unpinned the
    // conversation is dead in both directions, and that is the same state a
    // contact who merely reinstalled would leave behind — the commoner case by
    // far. Forgetting the peer puts it back to trust on first use.
    alice.forgetPeer(bob.aci);
    await bob.send(alice.aci, 'reachable again after accepting the new key');

    const recovered: IncomingMessage[] = [];
    await alice.catchUp((message) => {
      recovered.push(message);
    });
    assert.deepEqual(
      recovered.map((message) => message.body),
      ['reachable again after accepting the new key'],
      'unpinning must let the real contact through again',
    );

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

  test('a sealed request of the wrong shape never reaches the key agreement', async () => {
    const key = (await (await fetch(`${server.url}/v1/oblivious-key`)).json()) as { publicKey: string };
    const gatewayKey = PublicKey.deserialize(unb64(key.publicKey));

    // Correctly sealed and correctly addressed, but not the fixed request
    // layout. Because that layout is one fixed length, a wrong shape is a wrong
    // length, and a wrong length is refused before anything is decrypted —
    // which is the point: opening one of these is the first thing an
    // unauthenticated caller can make the gateway do, and it is a key
    // agreement.
    const sealed = gatewayKey.seal(bytes(randomBytes(128)), OBLIVIOUS_INFO);
    assert.notEqual(sealed.length, OBLIVIOUS_SEALED_BYTES);

    const response = await fetch(`${server.url}/v1/oblivious`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: sealed,
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, 'invalid_request');
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

/**
 * The gateway is never told a handle.
 *
 * What travels is a 32-byte hash and a zero-knowledge proof that the sender
 * knows a name producing it. The proof is what stops a hash being a name
 * anybody can claim without being able to use it, and the hash is what means a
 * gateway that is seized, subpoenaed or simply curious has no list of names to
 * give up — only something an adversary has to attack one name at a time.
 */
describe('the gateway stores handle hashes and never the handles', () => {
  test('a registered account leaves no plaintext name in the database', async () => {
    const account = await register('nohandle');
    assert.ok(isValidUsername(account.username), 'the client knows its own handle');

    // The strongest form this claim takes: the column is gone, so there is
    // nothing for a future query to accidentally start reading again.
    const columns = server.store['db']
      .prepare('PRAGMA table_info(accounts)')
      .all() as { name: string }[];
    assert.ok(
      !columns.some((c) => c.name === 'username'),
      'the accounts table must not carry a plaintext username column',
    );
    assert.ok(columns.some((c) => c.name === 'username_hash'));

    // And the hash it does hold is the hash of the handle the client chose.
    const row = server.store.accountByUsernameHash(usernameHash(account.username));
    assert.equal(row?.aci, account.aci);

    account.close();
  });

  test('two people may hold the same nickname', async () => {
    // The reason handles carry digits at all. Before this, the first person to
    // register a common Uzbek name took it from everybody else.
    const nickname = `sharednick${Date.now() % 100000}`;
    const first = await MillygramClient.register({
      serverUrl: server.url,
      databasePath: join(workdir, `${nickname}-1.db`),
      passphrase: 'a test passphrase',
      username: nickname,
    });
    const second = await MillygramClient.register({
      serverUrl: server.url,
      databasePath: join(workdir, `${nickname}-2.db`),
      passphrase: 'a test passphrase',
      username: nickname,
    });

    assert.notEqual(first.username, second.username, 'the same nickname must yield two handles');
    assert.notEqual(first.aci, second.aci);
    assert.ok(first.username.startsWith(`${nickname}.`));
    assert.ok(second.username.startsWith(`${nickname}.`));

    first.close();
    second.close();
  });

  test('a hash without a working proof is refused', async () => {
    // A hash on its own is a name somebody could reserve without being able to
    // use it. The proof is the whole of what stops that, so it has to be
    // checked rather than merely carried.
    const account = buildRegistration(unique('noproof').username);
    const forged = {
      ...account.body,
      usernameProof: b64(randomBytes(128)),
    };
    const response = await postJson('/v1/accounts', forged);
    assert.equal(response.status, 400, 'a proof that proves nothing must be refused');
    assert.equal(((await response.json()) as { error: string }).error, 'invalid_username_proof');
  });

  test('a bare nickname does not resolve', async () => {
    // Knowing somebody's nickname is not knowing their handle, so a wordlist of
    // names is not a contact list.
    const sender = await register('needsdigits');
    const target = await register('hasdigits');
    const nickname = target.username.slice(0, target.username.lastIndexOf('.'));

    await assert.rejects(
      () => sender.send(nickname, 'should not arrive'),
      'a nickname without its digits must not resolve to an account',
    );
    // The whole handle does resolve, so the refusal above is the digits and not
    // the account being missing.
    await sender.send(target.username, 'this one is addressed properly');

    sender.close();
    target.close();
  });
});

/**
 * Discovery is rationed far harder than re-contact.
 *
 * Turning a typed name into an account is the only route worth crawling, and
 * the honest volume for it is a few dozen lookups in the life of an install.
 * Reaching somebody already known carries an account id the device already
 * holds and never comes through here. That asymmetry is what lets the budget be
 * this small, and it is the mitigation the contact-discovery literature settled
 * on after rate limits alone were shown not to hold at scale.
 */
describe('directory discovery is rationed', () => {
  test('a burst of lookups is cut off well before a namespace can be swept', async () => {
    const gateway = await startServer({
      host: '127.0.0.1',
      port: 0,
      databasePath: join(workdir, 'discoverylimit.db'),
      rateLimits: { ...testRateLimits, directory: { capacity: 3, refillPerSecond: 1 / 3600 } },
      powDifficulty: TEST_POW_DIFFICULTY,
      registrationPowDifficulty: TEST_REGISTRATION_POW,
    });

    const prober = await MillygramClient.register({
      serverUrl: gateway.url,
      databasePath: join(workdir, 'prober.db'),
      passphrase: 'a test passphrase',
      username: 'prober',
    });

    // Three handles that parse but name nobody. Each is refused as not found,
    // and each still spends from the budget — a guess that missed is exactly
    // what a crawl is made of, so it has to cost the same as one that hit.
    const misses: string[] = [];
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await assert.rejects(() => prober.send(`ghost${attempt}.42`, 'nobody'));
      misses.push(`ghost${attempt}.42`);
    }
    assert.equal(misses.length, 3);

    // The budget is now empty and refills once an hour, so the next guess is
    // refused for a different reason than the three before it.
    await assert.rejects(
      () => prober.send('ghost9.42', 'nobody'),
      (error: Error) => /slow_down/.test(error.message),
      'a fourth lookup must be throttled, not merely answered not-found',
    );

    prober.close();
    await gateway.close();
  });
});

/**
 * Invites.
 *
 * Handles carry digits nobody can guess and there is no directory to browse, so
 * the only way to be found is for somebody to be told your name. An invite is
 * that, made transferable — and it deliberately does not involve the gateway,
 * because a link the gateway served would be a request it could watch, and
 * therefore a record of who was being introduced to whom.
 */
describe('an invite carries a handle without the gateway seeing it', () => {
  test('an invite round-trips to the handle it was made from', async () => {
    const account = await register('invited');
    const link = createUsernameLink(account.username);

    assert.ok(link.startsWith(USERNAME_LINK_PREFIX), 'an invite must be recognisable');
    assert.equal(usernameFromLink(link), account.username);

    // The handle must not sit in the token as a searchable string — that is the
    // whole reason the name is encrypted rather than simply written into it.
    assert.ok(!link.includes(account.username), 'the handle must not appear in the invite');

    account.close();
  });

  test('two invites for one handle are different tokens', async () => {
    // Each carries its own key, so two people given invites to the same account
    // hold nothing that links their two pieces of paper together.
    const account = await register('invitetwice');
    const first = createUsernameLink(account.username);
    const second = createUsernameLink(account.username);

    assert.notEqual(first, second);
    assert.equal(usernameFromLink(first), account.username);
    assert.equal(usernameFromLink(second), account.username);

    account.close();
  });

  test('an invite is a constant size whatever the handle', () => {
    // A short name and a long one produce the same token length, so the size of
    // an invite gives nothing away about the name inside it.
    const lengths = new Set(
      ['abc.42', 'dilnoza.42', `${'z'.repeat(32)}.999999`].map((u) => createUsernameLink(u).length),
    );
    assert.equal(lengths.size, 1, 'every invite must be the same length');
  });

  test('a damaged or foreign invite resolves to nothing rather than throwing', () => {
    // Every one of these arrives the same way — somebody pasting into a field —
    // so none of them is exceptional enough to be an exception.
    const good = createUsernameLink('dilnoza.42');
    assert.equal(usernameFromLink(good.slice(0, -4)), null, 'a truncated paste');
    assert.equal(usernameFromLink(`${good.slice(0, -2)}AA`), null, 'a tampered ciphertext');
    assert.equal(usernameFromLink(good.slice(USERNAME_LINK_PREFIX.length)), null, 'no prefix');
    assert.equal(usernameFromLink('mg1:not-base64!!'), null, 'not base64url');
    assert.equal(usernameFromLink('https://example.invalid/u/abc'), null, 'something else');
    assert.equal(usernameFromLink(''), null, 'nothing at all');
  });
});
