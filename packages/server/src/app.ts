import Fastify, { LogController, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import {
  AuthRequest,
  Envelope,
  MAX_ENVELOPE_BYTES,
  OBLIVIOUS_REQUEST_BYTES,
  ONE_TIME_PREKEY_BATCH,
  PADDED_ENVELOPE_BYTES,
  RegisterRequest,
  ReplenishRequest,
  Username,
  b64,
  decodeObliviousRequest,
  registrationSigningPayload,
  verifyRegistrationWork,
  unb64,
  verifyProofOfWork,
  type StoredEnvelope,
} from '@millygram/protocol';
import { z } from 'zod';
import type { ServerConfig } from './config.js';
import type { Store } from './db.js';
import { Authenticator, type AuthenticatedCaller } from './auth.js';
import { ServerIdentity, parseIdentityKey, verifyPreKeySignature } from './identity.js';
import { RateLimiter } from './ratelimit.js';

/**
 * The key for a limiter that counts the whole gateway rather than one caller.
 * A constant, so every request shares the bucket.
 */
const GLOBAL = 'gateway';

export interface DeliveryHub {
  notify(bucketId: number, envelope: StoredEnvelope): void;
}

export interface AppDeps {
  config: ServerConfig;
  store: Store;
  identity: ServerIdentity;
  authenticator: Authenticator;
  hub: DeliveryHub;
}

const SinceQuery = z.object({ since: z.coerce.number().int().min(0).default(0) });

export function buildApp(deps: AppDeps): FastifyInstance {
  const { config, store, identity, authenticator, hub } = deps;

  const app = Fastify({
    bodyLimit: MAX_ENVELOPE_BYTES * 4,
    trustProxy: config.trustProxy,
    // Per-request log lines are off entirely. Even with the serializers below,
    // an access log is a running record of who contacted the relay and when —
    // the exact metadata this design exists not to keep.
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: process.env.MG_LOG_LEVEL ?? 'warn',
      // The default serializers record remoteAddress and the full URL. Both are
      // sender metadata, and metadata written to a log file is metadata that can
      // be seized, so neither is ever serialized here.
      serializers: {
        req: (request: { method: string; routeOptions?: { url?: string | undefined } }) => ({
          method: request.method,
          route: request.routeOptions?.url ?? null,
        }),
        res: (reply: { statusCode: number }) => ({ statusCode: reply.statusCode }),
      },
    },
  });

  // Sealed submissions arrive as raw bytes, not JSON.
  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer', bodyLimit: OBLIVIOUS_REQUEST_BYTES + 1024 },
    (_request, body, done) => done(null, body),
  );

  const limits = config.rateLimits;
  /**
   * Every limiter, so the sweep cannot miss one.
   *
   * It already had: this list was written by hand and a seventh limiter was
   * added without being added here, so its buckets were never dropped — one
   * entry per account that ever authenticated, held forever. Collecting them
   * at the point of construction makes that impossible rather than merely
   * unlikely.
   */
  const allLimiters: RateLimiter[] = [];
  const track = <T extends RateLimiter>(limiter: T): T => {
    allLimiters.push(limiter);
    return limiter;
  };

  const registrationLimiter = track(new RateLimiter(limits.registration.capacity, limits.registration.refillPerSecond));
  const authLimiter = track(new RateLimiter(limits.auth.capacity, limits.auth.refillPerSecond));
  const authPerAccountLimiter = track(new RateLimiter(
    limits.authPerAccount.capacity,
    limits.authPerAccount.refillPerSecond,
  ));
  const directoryLimiter = track(new RateLimiter(limits.directory.capacity, limits.directory.refillPerSecond));
  const inboundLimiter = track(new RateLimiter(limits.inbound.capacity, limits.inbound.refillPerSecond));
  const bundlePerCaller = track(new RateLimiter(
    limits.preKeyBundlePerCaller.capacity,
    limits.preKeyBundlePerCaller.refillPerSecond,
  ));
  const bundlePerTarget = track(new RateLimiter(
    limits.preKeyBundlePerTarget.capacity,
    limits.preKeyBundlePerTarget.refillPerSecond,
  ));

  const sweep = setInterval(() => {
    for (const limiter of allLimiters) limiter.sweep();
  }, 60_000);
  sweep.unref();
  app.addHook('onClose', async () => clearInterval(sweep));

  function requireAuth(request: FastifyRequest, reply: FastifyReply): AuthenticatedCaller | null {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      reply.code(401).send({ error: 'unauthenticated' });
      return null;
    }
    const caller = authenticator.verifyToken(header.slice('Bearer '.length));
    if (!caller) {
      reply.code(401).send({ error: 'unauthenticated' });
      return null;
    }
    return caller;
  }

  app.get('/v1/trust-root', async () => ({ trustRoot: b64(identity.trustRootPublic.serialize()) }));

  app.post('/v1/accounts', async (request, reply) => {
    // Deliberately not keyed on the caller's address. Whole Uzbek carriers sit
    // behind a handful of public addresses, so rationing signups per address
    // rations them per carrier. This is a ceiling for the gateway as a whole;
    // what an individual registration costs is the work attached to it.
    if (!registrationLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    const parsed = RegisterRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });
    const body = parsed.data;

    const skew = Math.abs(Date.now() - body.timestamp);
    if (skew > 5 * 60 * 1000) return reply.code(400).send({ error: 'clock_skew' });

    const identityKey = parseIdentityKey(unb64(body.identityKey));
    if (!identityKey) return reply.code(400).send({ error: 'invalid_identity_key' });

    const { signature, workNonce, ...unsigned } = body;
    const payload = registrationSigningPayload(unsigned);

    // Checked before the signature, because it is the cheaper of the two and
    // is what makes flooding this endpoint expensive. The difficulty travels
    // with the refusal so a client can pay more without needing a new build.
    if (!verifyRegistrationWork(payload, workNonce, config.registrationPowDifficulty)) {
      return reply
        .code(400)
        .send({ error: 'work_required', difficulty: config.registrationPowDifficulty });
    }

    if (!verifyPreKeySignature(identityKey, payload, unb64(signature))) {
      return reply.code(400).send({ error: 'invalid_signature' });
    }
    if (!verifyPreKeySignature(identityKey, unb64(body.signedPreKey.publicKey), unb64(body.signedPreKey.signature))) {
      return reply.code(400).send({ error: 'invalid_signed_prekey' });
    }
    if (!verifyPreKeySignature(identityKey, unb64(body.kyberPreKey.publicKey), unb64(body.kyberPreKey.signature))) {
      return reply.code(400).send({ error: 'invalid_kyber_prekey' });
    }

    if (store.accountByUsername(body.username)) return reply.code(409).send({ error: 'username_taken' });

    const { aci, bucketId } = store.createAccount({
      username: body.username,
      deviceId: body.deviceId,
      registrationId: body.registrationId,
      identityKey: unb64(body.identityKey),
      signedPreKey: {
        keyId: body.signedPreKey.keyId,
        publicKey: unb64(body.signedPreKey.publicKey),
        signature: unb64(body.signedPreKey.signature),
      },
      kyberPreKey: {
        keyId: body.kyberPreKey.keyId,
        publicKey: unb64(body.kyberPreKey.publicKey),
        signature: unb64(body.kyberPreKey.signature),
      },
      oneTimePreKeys: body.oneTimePreKeys.map((k) => ({ keyId: k.keyId, publicKey: unb64(k.publicKey) })),
    }, config.bucketSize);

    return reply.code(201).send({
      aci,
      bucketId,
      trustRoot: b64(identity.trustRootPublic.serialize()),
      powDifficulty: config.powDifficulty,
    });
  });

  app.get('/v1/accounts/challenge', async (request, reply) => {
    if (!authLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    const parsed = z.object({ aci: z.uuid() }).safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    // Issued whether or not the account exists, so this endpoint cannot be used
    // to enumerate which account identifiers are real.
    return authenticator.issueChallenge(parsed.data.aci);
  });

  app.post('/v1/accounts/auth', async (request, reply) => {
    // The global bucket pays for signature verification, which is CPU and so a
    // resource of the gateway rather than of any address. Keying this on the
    // caller's address locked out everyone behind a carrier NAT.
    if (!authLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    const parsed = AuthRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });
    const { aci, deviceId, nonce, signature } = parsed.data;

    if (!authenticator.verifyChallengeResponse(aci, deviceId, nonce, signature)) {
      return reply.code(401).send({ error: 'unauthenticated' });
    }

    // Charged only once a signature has proved which account is asking, and
    // only on success. Charging a failure would let anyone lock a chosen
    // account out by sending rubbish signatures in its name.
    if (!authPerAccountLimiter.tryConsume(aci)) {
      return reply.code(429).send({ error: 'slow_down' });
    }
    return authenticator.mintToken(aci, deviceId);
  });

  app.get('/v1/directory/:username', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;
    if (!directoryLimiter.tryConsume(caller.aci)) return reply.code(429).send({ error: 'slow_down' });

    const parsed = z.object({ username: Username }).safeParse(request.params);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    const account = store.accountByUsername(parsed.data.username);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    return { aci: account.aci, deviceId: account.device_id, bucketId: account.bucket_id };
  });

  app.get('/v1/keys/:aci', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const parsed = z.object({ aci: z.uuid() }).safeParse(request.params);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    // Looked up before anything is charged, because the limiters keep a bucket
    // per key and one of those keys is a caller/target pair. Charging first
    // meant a request for an account that does not exist still created two
    // buckets, each held for the best part of an hour, and neither of them
    // throttling anything: a fresh key starts full, so a caller naming a new
    // random identifier every time was never refused. That is unbounded memory
    // for the cost of a 404. Identifiers are not guessable, so refusing unknown
    // ones before charging closes it.
    const account = store.accountByAci(parsed.data.aci);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    // Serving a bundle consumes one of the target's one-time prekeys. Both
    // limits matter: the per-caller one stops a single account draining a
    // victim, and the per-target one stops the same drain from a fleet of
    // accounts. Together they hold the drain rate below the rate at which the
    // target's client replenishes.
    if (!bundlePerCaller.tryConsume(`${caller.aci}->${parsed.data.aci}`)) {
      return reply.code(429).send({ error: 'slow_down' });
    }
    if (!bundlePerTarget.tryConsume(parsed.data.aci)) {
      return reply.code(429).send({ error: 'slow_down' });
    }

    const signed = store.signedPreKey(account.aci);
    const kyber = store.kyberPreKey(account.aci);
    if (!signed || !kyber) return reply.code(409).send({ error: 'keys_unavailable' });

    const oneTime = store.takeOneTimePreKey(account.aci);

    return {
      aci: account.aci,
      deviceId: account.device_id,
      bucketId: account.bucket_id,
      registrationId: account.registration_id,
      identityKey: b64(account.identity_key),
      signedPreKey: {
        keyId: signed.key_id,
        publicKey: b64(signed.public_key),
        signature: b64(signed.signature),
      },
      kyberPreKey: {
        keyId: kyber.key_id,
        publicKey: b64(kyber.public_key),
        signature: b64(kyber.signature),
      },
      oneTimePreKey: oneTime
        ? { keyId: oneTime.key_id, publicKey: b64(oneTime.public_key) }
        : null,
    };
  });

  app.put('/v1/keys', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const parsed = ReplenishRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    const account = store.accountByAci(caller.aci);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    const identityKey = parseIdentityKey(account.identity_key);
    if (!identityKey) return reply.code(500).send({ error: 'corrupt_account' });

    const { signedPreKey, kyberPreKey, oneTimePreKeys } = parsed.data;

    if (signedPreKey) {
      if (!verifyPreKeySignature(identityKey, unb64(signedPreKey.publicKey), unb64(signedPreKey.signature))) {
        return reply.code(400).send({ error: 'invalid_signed_prekey' });
      }
      store.writeSignedPreKey(caller.aci, {
        keyId: signedPreKey.keyId,
        publicKey: unb64(signedPreKey.publicKey),
        signature: unb64(signedPreKey.signature),
      });
    }

    if (kyberPreKey) {
      if (!verifyPreKeySignature(identityKey, unb64(kyberPreKey.publicKey), unb64(kyberPreKey.signature))) {
        return reply.code(400).send({ error: 'invalid_kyber_prekey' });
      }
      store.writeKyberPreKey(caller.aci, {
        keyId: kyberPreKey.keyId,
        publicKey: unb64(kyberPreKey.publicKey),
        signature: unb64(kyberPreKey.signature),
      });
    }

    if (oneTimePreKeys?.length) {
      if (store.countOneTimePreKeys(caller.aci) + oneTimePreKeys.length > ONE_TIME_PREKEY_BATCH * 2) {
        return reply.code(409).send({ error: 'too_many_prekeys' });
      }
      store.addOneTimePreKeys(
        caller.aci,
        oneTimePreKeys.map((k) => ({ keyId: k.keyId, publicKey: unb64(k.publicKey) })),
      );
    }

    return reply.code(204).send();
  });

  app.get('/v1/keys/count', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;
    return { oneTimePreKeys: store.countOneTimePreKeys(caller.aci) };
  });

  app.get('/v1/certificate/delivery', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const account = store.accountByAci(caller.aci);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    const identityKey = parseIdentityKey(account.identity_key);
    if (!identityKey) return reply.code(500).send({ error: 'corrupt_account' });

    const { certificate, expiresAt } = identity.issueSenderCertificate(
      account.aci,
      account.device_id,
      identityKey,
    );
    return { certificate: b64(certificate.serialize()), expiresAt };
  });

  /**
   * Submission carries no identity at all — no token, no account, no key tied
   * to a person. It is addressed to a bucket, not a recipient, and the cost of
   * sending is paid in CPU so that anonymity does not turn the relay into an
   * open drain.
   */
  interface SubmitOutcome {
    status: number;
    body: Record<string, unknown> | null;
  }

  /**
   * The one place a submission is checked, shared by the direct and the
   * oblivious route. Two copies of this would be two things to keep in step,
   * and the one that drifted would be the one with the hole in it.
   */
  /**
   * Check order is load-bearing.
   *
   * The rate limit is consumed LAST, only once a submission has proved it is
   * well-formed and has paid its proof of work. Consuming it first — as this
   * did originally — let anyone exhaust a bucket's whole delivery budget with
   * zero-cost garbage, denying service to every member of that bucket without
   * spending a single hash.
   */
  function acceptEnvelope(bucketId: number, content: Uint8Array, nonce: number): SubmitOutcome {
    // Every envelope is exactly this size. Refusing any other length means a
    // client cannot opt out of padding, deliberately or by accident, and leave
    // a length-distinguishable envelope sitting in someone else's bucket.
    if (content.length !== PADDED_ENVELOPE_BYTES) {
      return { status: 400, body: { error: 'envelope_must_be_padded', expected: PADDED_ENVELOPE_BYTES } };
    }

    if (!verifyProofOfWork(bucketId, content, nonce, config.powDifficulty)) {
      return { status: 400, body: { error: 'insufficient_proof_of_work', difficulty: config.powDifficulty } };
    }

    // Envelopes for a bucket nobody occupies are refused; otherwise the table
    // becomes free storage for anyone with a spare integer.
    if (store.bucketMembers(bucketId) === 0) return { status: 404, body: { error: 'not_found' } };

    // A proof of work is only expensive the first time it is computed. Without
    // this, an observer who captured one valid submission could replay it
    // indefinitely, and every member of the bucket would download the same
    // envelope again each time.
    if (!store.rememberSubmission(content)) return { status: 409, body: { error: 'duplicate_submission' } };

    if (!inboundLimiter.tryConsume(String(bucketId))) return { status: 429, body: { error: 'slow_down' } };

    const row = store.enqueue(bucketId, content);
    hub.notify(bucketId, { seq: row.seq, content: b64(row.content), arrivedAt: row.arrived_at });
    return { status: 202, body: null };
  }

  app.put('/v1/messages', async (request, reply) => {
    const parsed = Envelope.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    const { bucketId, content, nonce } = parsed.data;
    const outcome = acceptEnvelope(bucketId, unb64(content), nonce);
    return reply.code(outcome.status).send(outcome.body ?? '');
  });

  app.get('/v1/oblivious-key', async () => ({ publicKey: b64(identity.obliviousPublic.serialize()) }));

  /**
   * The oblivious route. Reached through a relay run by someone else, so the
   * address on the connection belongs to that relay and not to a sender. The
   * gateway can open the request but does not know who sent it; the relay knows
   * who sent it but cannot open it.
   */
  app.post('/v1/oblivious', async (request, reply) => {
    const sealed = request.body;
    if (!Buffer.isBuffer(sealed)) return reply.code(400).send({ error: 'invalid_request' });

    const plain = identity.openOblivious(sealed);
    if (!plain) return reply.code(400).send({ error: 'undecryptable' });

    const decoded = decodeObliviousRequest(plain);
    if (!decoded) return reply.code(400).send({ error: 'malformed_oblivious_request' });

    const outcome = acceptEnvelope(decoded.bucketId, decoded.content, decoded.nonce);
    return reply.code(outcome.status).send(outcome.body ?? '');
  });

  app.get('/v1/messages', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const query = SinceQuery.safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: 'invalid_request' });

    const account = store.accountByAci(caller.aci);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    const rows = store.since(account.bucket_id, query.data.since);
    return {
      envelopes: rows.map((row) => ({
        seq: row.seq,
        content: b64(row.content),
        arrivedAt: row.arrived_at,
      })),
    };
  });

  app.get('/v1/parameters', async () => ({
    powDifficulty: config.powDifficulty,
    paddedPayloadBytes: PADDED_ENVELOPE_BYTES,
    bucketSize: config.bucketSize,
  }));

  return app;
}
