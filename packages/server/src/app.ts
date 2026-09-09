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
  UsernameHash,
  verifyUsernameProof,
  b64,
  decodeObliviousRequest,
  OBLIVIOUS_SEALED_BYTES,
  AttachNumberRequest,
  StartRecoveryRequest,
  CompleteRecoveryRequest,
  RECOVERY_CODE_DIGITS,
  RECOVERY_CODE_TTL_MS,
  recoverySigningPayload,
  registrationSigningPayload,
  verifyRegistrationWork,
  unb64,
  verifyProofOfWork,
  type StoredEnvelope,
} from '@millygram/protocol';
import { randomInt } from 'node:crypto';
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

/**
 * Sends a recovery code to a number.
 *
 * Left to the operator because it is the one part of this system that cannot be
 * built here: it needs an SMS account somewhere, and whoever provides it sees
 * every number that recovers an account. That is a second party holding the
 * link this design otherwise avoids, and it is unavoidable if numbers are used
 * at all — worth knowing before choosing a provider, and worth choosing one in
 * the same jurisdiction as the users rather than a cheaper one elsewhere.
 */
export type RecoveryCodeSender = (phoneNumber: string, code: string) => Promise<void> | void;

export interface AppDeps {
  config: ServerConfig;
  store: Store;
  identity: ServerIdentity;
  authenticator: Authenticator;
  hub: DeliveryHub;
  /** Omitted, recovery accepts requests and delivers nothing. See the type. */
  sendRecoveryCode?: RecoveryCodeSender;
}

const SinceQuery = z.object({ since: z.coerce.number().int().min(0).default(0) });

export function buildApp(deps: AppDeps): FastifyInstance {
  const { config, store, identity, authenticator, hub } = deps;

  // Not a silent no-op: an operator who has enabled recovery without wiring up
  // delivery has an account-recovery route that accepts every request and never
  // helps anybody, and would find out from their users.
  const deliverRecoveryCode: RecoveryCodeSender =
    deps.sendRecoveryCode ??
    (() => {
      app.log.error('a recovery code was requested but no sender is configured; it was discarded');
    });

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
  const challengeLimiter = track(
    new RateLimiter(limits.challenge.capacity, limits.challenge.refillPerSecond),
  );
  const authPerAccountLimiter = track(new RateLimiter(
    limits.authPerAccount.capacity,
    limits.authPerAccount.refillPerSecond,
  ));
  const directoryLimiter = track(new RateLimiter(limits.directory.capacity, limits.directory.refillPerSecond));
  const inboundLimiter = track(new RateLimiter(limits.inbound.capacity, limits.inbound.refillPerSecond));

  /**
   * The proof of work a submission to this bucket must carry right now.
   *
   * Flat while the bucket is more than half full, so ordinary traffic and
   * ordinary bursts pay nothing extra, then climbing to the configured maximum
   * as the last half is spent. A ramp rather than a cliff: the cost arrives
   * gradually as evidence accumulates that a bucket is under pressure, instead
   * of everyone paying full price the moment the budget is empty.
   *
   * Reads the budget without spending it. Pricing a submission must not itself
   * consume the thing being priced.
   */
  function inboundDifficulty(bucketId: number, now = Date.now()): number {
    if (config.inboundPowEscalationMax <= 0) return config.powDifficulty;
    const share = inboundLimiter.remaining(String(bucketId), now) / limits.inbound.capacity;
    if (share >= 0.5) return config.powDifficulty;
    const spent = (0.5 - Math.max(0, share)) / 0.5;
    return config.powDifficulty + Math.ceil(spent * config.inboundPowEscalationMax);
  }
  const attachLimiter = track(
    new RateLimiter(limits.attachNumber.capacity, limits.attachNumber.refillPerSecond),
  );
  const recoveryPerNumberLimiter = track(
    new RateLimiter(limits.recoveryPerNumber.capacity, limits.recoveryPerNumber.refillPerSecond),
  );
  const recoveryLimiter = track(
    new RateLimiter(limits.recovery.capacity, limits.recovery.refillPerSecond),
  );
  const recoveryCompleteLimiter = track(
    new RateLimiter(limits.recoveryComplete.capacity, limits.recoveryComplete.refillPerSecond),
  );
  const obliviousLimiter = track(
    new RateLimiter(limits.oblivious.capacity, limits.oblivious.refillPerSecond),
  );
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

    // A hash on its own is a name anybody could claim without being able to use
    // it, so the claim is only worth considering once the proof stands up. It is
    // checked before the bucket is charged, like everything else on this route.
    if (!verifyUsernameProof(unb64(body.usernameProof), unb64(body.usernameHash))) {
      return reply.code(400).send({ error: 'invalid_username_proof' });
    }

    // Charged here, at the very end, and deliberately not keyed on the caller's
    // address: whole Uzbek carriers sit behind a handful of public addresses, so
    // rationing signups per address rations them per carrier. What an individual
    // registration costs is the proof of work attached to it, and this bucket is
    // only a circuit breaker on the registrations that actually happened.
    //
    // The order is the security property. Charging it as the first statement of
    // the route — before the body was even parsed, let alone before the work was
    // proved and the three signatures checked — meant a request that had paid
    // for nothing at all still spent from the gateway's whole signup budget, so
    // a couple of hundred bytes of rubbish, repeated, closed registration for
    // everybody for free. It is the same bargain the submission path already
    // makes in acceptEnvelope: prove the work first, charge the bucket last.
    if (!registrationLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    // Only the hash is stored. The gateway has never been told the name and
    // cannot be made to produce it. Null means that hash is already claimed, and
    // the client comes back with the next candidate libsignal gave it.
    const created = store.createAccount({
      usernameHash: unb64(body.usernameHash),
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
    if (!created) return reply.code(409).send({ error: 'username_taken' });
    const { aci, bucketId } = created;

    return reply.code(201).send({
      aci,
      bucketId,
      trustRoot: b64(identity.trustRootPublic.serialize()),
      powDifficulty: config.powDifficulty,
      // The account's own avatar seed. Returned so a device can draw what
      // everyone else sees of it without looking itself up in the directory,
      // which would be an odd request for a client to have to make.
      avatarSeed: b64(store.avatarSeed(aci) ?? Buffer.alloc(0)),
    });
  });

  app.get('/v1/accounts/challenge', async (request, reply) => {
    const parsed = z.object({ aci: z.uuid() }).safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    // A bucket of its own, no longer the one the auth route spends. Sharing them
    // meant a flood aimed at either half of login closed the other, and since a
    // usable nonce can only be obtained here, posting rubbish at a route nobody
    // wanted to use was enough to stop everybody signing in. Charged after the
    // query has parsed, so a request that is not even asking about an account
    // identifier costs nothing.
    if (!challengeLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    // Issued whether or not the account exists, so this endpoint cannot be used
    // to enumerate which account identifiers are real.
    return authenticator.issueChallenge(parsed.data.aci);
  });

  app.post('/v1/accounts/auth', async (request, reply) => {
    const parsed = AuthRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });
    const { aci, deviceId, nonce, signature } = parsed.data;

    // The nonce is looked up and spent before any public-key work happens, so a
    // request naming one this gateway never issued — or one already redeemed — is
    // refused here without costing CPU and without touching a shared bucket.
    if (!authenticator.verifyChallengeResponse(aci, deviceId, nonce, signature)) {
      return reply.code(401).send({ error: 'unauthenticated' });
    }

    // The global bucket pays for the verification that has just succeeded, which
    // is CPU and so a resource of the gateway rather than of any address. Keying
    // this on the caller's address locked out everyone behind a carrier NAT.
    //
    // Charged after the check rather than before it. Spending it first meant
    // unsigned junk drained it, and with the bucket at zero nobody could log in
    // — roughly fifty rubbish posts a second was the whole price of that. What
    // still bounds the verifications an attacker can force is the challenge
    // route's own budget, because every usable nonce has to be fetched from
    // there first and that route now has a separate one.
    if (!authLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    // A self-reported environment signal, weighed here and nowhere trusted.
    // The default is to let the account in — the checks that produced it are
    // all defeatable, so refusing on them punishes a misfiring cheap handset
    // more reliably than it stops an attacker, who reports "clean" regardless.
    // An operator who wants the stricter posture sets
    // refuseTamperedEnvironments; even then it turns away only the honest
    // client that admitted the truth, which is why it is off by default.
    const environment = parsed.data.environment;
    if (environment && environment !== 'clean') {
      // The account identifier is deliberately not in this line. Written beside
      // the flags it would read "this account was online at this minute, from a
      // rooted handset" — a durable, seizable record of presence, on disk, in a
      // gateway that keeps no access log, no delivery acknowledgements and
      // bucketed mailboxes precisely so that there is nothing of that shape to
      // hand over. It would also fall hardest on ordinary people here, since the
      // handsets that raise the flag are the old, rooted and sideloaded ones
      // rather than an attacker's, who reports "clean" and appears nowhere.
      //
      // Debug rather than the default warn, so an operator who genuinely wants
      // to know whether flagged environments are turning up has to ask for it,
      // and learns only that they are and which flags — never whose. An
      // unattributed counter would leak less still, but there is nowhere here to
      // read one from: this gateway exposes no metrics endpoint, and adding one
      // to carry this single number would be a second place operational data
      // lives and a second thing to seize.
      app.log.debug({ environment }, 'a device reported a flagged environment');

      if (config.refuseTamperedEnvironments) {
        const blocked = environment
          .split(',')
          .some((f) => config.blockedEnvironmentFlags.includes(f));
        if (blocked) {
          // The one place naming the account is defensible. The operator has
          // explicitly turned enforcement on, somebody was actually turned away,
          // and a refusal nobody can afterwards explain is worse for the user
          // than the record it leaves. It is written only on the refusal and
          // only under that configuration; on the default path, where the device
          // is let through, nothing about who is written anywhere.
          app.log.warn({ aci, environment }, 'refused an authentication from a blocked environment');
          return reply.code(403).send({ error: 'environment_blocked' });
        }
      }
    }

    // Charged only once a signature has proved which account is asking, and
    // only on success. Charging a failure would let anyone lock a chosen
    // account out by sending rubbish signatures in its name.
    if (!authPerAccountLimiter.tryConsume(aci)) {
      return reply.code(429).send({ error: 'slow_down' });
    }
    return authenticator.mintToken(aci, deviceId);
  });

  /**
   * Resolving a handle somebody typed. The one route that turns a name into an
   * account, and therefore the only one worth crawling.
   *
   * Its budget is deliberately far smaller than it looks like it should be, and
   * the reason is that discovery and re-contact are different actions with wildly
   * different honest volumes. Finding somebody new is a thing a person does by
   * typing a name they were given, a few dozen times in the life of an install.
   * Reaching somebody already known needs no name at all — the account id is
   * already on the device, and the prekey route that takes it has its own,
   * looser budget. So the expensive path can be rationed hard without any real
   * user feeling it, which is the asymmetry the contact-discovery literature
   * settled on after rate limits alone were shown not to hold: WhatsApp was
   * enumerated at over a hundred million lookups an hour against limits that
   * were, on paper, in place.
   *
   * Charged after the name is parsed, so a malformed handle is refused on its
   * merits and costs the caller nothing — the same ordering the rest of this
   * file now follows.
   */
  app.get('/v1/directory/:usernameHash', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const parsed = z.object({ usernameHash: UsernameHash }).safeParse(request.params);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    if (!directoryLimiter.tryConsume(caller.aci)) return reply.code(429).send({ error: 'slow_down' });

    const account = store.accountByUsernameHash(unb64(parsed.data.usernameHash));
    if (!account) return reply.code(404).send({ error: 'not_found' });

    return {
      aci: account.aci,
      deviceId: account.device_id,
      bucketId: account.bucket_id,
      avatarSeed: b64(store.avatarSeed(account.aci) ?? Buffer.alloc(0)),
    };
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
      // Served with the keys because that is a request the client already
      // makes, so an avatar costs no round trip and reveals no extra interest
      // in anybody. It arrives from the gateway and never from the peer.
      avatarSeed: b64(store.avatarSeed(account.aci) ?? Buffer.alloc(0)),
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
   * Whether the relay has room for another envelope in this bucket.
   *
   * Both ceilings refuse the new write and never evict an old one. An envelope
   * already in the table may be the only copy of something a member has not
   * collected yet, and the relay cannot tell which — it does not know who an
   * envelope is for and is not allowed to find out. So the thing that gives
   * way is the submission that has not happened yet, whose sender is told,
   * rather than the message that already arrived, whose recipient would never
   * know it existed.
   *
   * Answered with 429 because that is what a sender should do about it — come
   * back later — and because the alternative, a 5xx, reads to every relay and
   * client in the path as "this gateway is broken" rather than "this gateway
   * is full". The error string is what tells the two ceilings apart in an
   * operator's logs.
   */
  function storageRefusal(bucketId: number): SubmitOutcome | null {
    const { inBucket, total, buckets } = store.envelopeLoad(bucketId);
    if (inBucket >= config.maxEnvelopesPerBucket) {
      return { status: 429, body: { error: 'bucket_full' } };
    }
    if (total < config.maxEnvelopesTotal) return null;

    // Full. Which bucket gets refused now decides who this costs, so it is the
    // ones above an equal share of the whole ceiling — the buckets that filled
    // it. A bucket under its share is still admitted, which is what keeps a
    // flood from turning a disk ceiling into a gateway-wide outage, and it
    // still terminates: nothing may exceed its share, so the total settles at
    // the ceiling plus at most one envelope per bucket.
    const share = config.maxEnvelopesTotal / Math.max(1, buckets);
    if (inBucket < share) return null;
    return { status: 429, body: { error: 'relay_full' } };
  }

  /**
   * Check order is load-bearing.
   *
   * The rate limit is consumed LAST, only once a submission has proved it is
   * well-formed and has paid its proof of work. Consuming it first — as this
   * did originally — let anyone exhaust a bucket's whole delivery budget with
   * zero-cost garbage, denying service to every member of that bucket without
   * spending a single hash.
   *
   * Replay defence is split across that limiter for the same reason, and it is
   * the more delicate half. The question "have I seen these bytes before" is
   * asked BEFORE the limiter, because a replay carries no fresh work — it is a
   * copy of a proof somebody else already paid for — and if the limiter ran
   * first, a replay would spend a token out of the bucket's shared budget
   * before anything noticed what it was. That is a way to hold sixteen people's
   * inbound down at no cost at all, and it would undo the adaptive pricing
   * above, since one envelope solved once at the top difficulty could then be
   * replayed forever.
   *
   * The row that records the answer is written AFTER the limiter, because
   * writing it before meant the digest table grew at the full proof-of-work
   * rate even for submissions the limiter refused — measured at 200 digest rows
   * for 60 delivered envelopes, and unbounded above that. A digest is now
   * written only for an envelope that was actually stored, so the replay table
   * can never outgrow the table it protects and needs no ceiling of its own.
   *
   * Reading and writing are therefore not interchangeable here, and neither is
   * a swap of the two lines. Splitting them is what bounds one without opening
   * the other.
   */
  function acceptEnvelope(bucketId: number, content: Uint8Array, nonce: number): SubmitOutcome {
    // Every envelope is exactly this size. Refusing any other length means a
    // client cannot opt out of padding, deliberately or by accident, and leave
    // a length-distinguishable envelope sitting in someone else's bucket.
    if (content.length !== PADDED_ENVELOPE_BYTES) {
      return { status: 400, body: { error: 'envelope_must_be_padded', expected: PADDED_ENVELOPE_BYTES } };
    }

    // What this submission costs, which depends on how much of the bucket's
    // shared budget is left. A quiet bucket charges the base difficulty; one
    // that is being drained charges up to inboundPowEscalationMax bits more, so
    // the flooder holding sixteen people's inbound down pays 2^that for the
    // privilege. Priced before the work is checked, so the cost is decided by
    // the state of the bucket and never by anything the caller sent.
    const required = inboundDifficulty(bucketId);
    if (!verifyProofOfWork(bucketId, content, nonce, required)) {
      return { status: 400, body: { error: 'insufficient_proof_of_work', difficulty: required } };
    }

    // Envelopes for a bucket nobody occupies are refused; otherwise the table
    // becomes free storage for anyone with a spare integer.
    if (store.bucketMembers(bucketId) === 0) return { status: 404, body: { error: 'not_found' } };

    // A proof of work is only expensive the first time it is computed. Without
    // this, an observer who captured one valid submission could replay it
    // indefinitely, and every member of the bucket would download the same
    // envelope again each time. Asked here, ahead of everything a submission
    // can spend, so that a replay costs the bucket nothing. See the note above.
    if (store.hasSubmission(content)) return { status: 409, body: { error: 'duplicate_submission' } };

    // Checked before the limiter too, so that a bucket at its ceiling is not
    // also charged a token for every submission it is going to refuse.
    const full = storageRefusal(bucketId);
    if (full) return full;

    if (!inboundLimiter.tryConsume(String(bucketId))) return { status: 429, body: { error: 'slow_down' } };

    // The authoritative half of the dedupe, and the only one that writes.
    // Everything from the read above to here runs without yielding, so this can
    // only disagree with it if a second process is writing to the same database
    // — which nothing here does. It stays an atomic INSERT OR IGNORE rather
    // than a bare insert so that if one ever did, the loser is a 409 and not a
    // second copy fanned out to the bucket.
    if (!store.rememberSubmission(content)) return { status: 409, body: { error: 'duplicate_submission' } };

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

  /**
   * Attaching a number so the account can be recovered on another handset.
   *
   * Never part of registration, and never implied by it. Signing up asks for
   * nothing at all, and this is a separate thing somebody chooses knowing what
   * it costs: in a country where a SIM is registered against a passport, a
   * gateway that can answer "which account has this number" is a gateway
   * holding a link between an account and a named person. The client says so
   * before it calls this.
   */
  app.put('/v1/account/recovery-number', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;

    const parsed = AttachNumberRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    // Refused rather than taken over. This does tell an authenticated caller
    // that some account already uses this number, which is a real if narrow
    // enumeration oracle — the alternative was letting them silently steal it,
    // and between the two there is no contest. It is rate limited per account
    // so a probe costs an account and time rather than a request.
    if (!attachLimiter.tryConsume(caller.aci)) {
      return reply.code(429).send({ error: 'slow_down' });
    }
    if (!store.attachRecoveryNumber(identity.numberMac(parsed.data.phoneNumber), caller.aci)) {
      return reply.code(409).send({ error: 'number_in_use' });
    }
    return reply.code(204).send();
  });

  app.delete('/v1/account/recovery-number', async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (!caller) return;
    store.detachRecoveryNumber(caller.aci);
    return reply.code(204).send();
  });

  /**
   * Asks for a code to be sent to a number.
   *
   * Answers the same way whether or not the number is attached to anything. The
   * alternative tells anyone holding a list of numbers which of them use this
   * service, which is the enumeration that not asking for a number at signup
   * exists to prevent — it would be a strange thing to give away here instead.
   */
  app.post('/v1/recovery/start', async (request, reply) => {
    const parsed = StartRecoveryRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });

    const mac = identity.numberMac(parsed.data.phoneNumber);
    if (!recoveryPerNumberLimiter.tryConsume(mac.toString('base64'))) {
      return reply.code(429).send({ error: 'slow_down' });
    }

    // Last of the checks, and still deliberately before the lookup. Charging it
    // as the first statement of the route meant sixty malformed bodies emptied
    // the gateway's entire recovery budget and one more every thirty seconds
    // held it there, so nobody who had actually lost a phone could start a
    // recovery — the cheapest possible denial of the one route people reach at
    // their worst moment.
    //
    // Moving it past the lookup instead would have been worse than leaving it
    // where it was. A 429 would then only ever be returned for a number that is
    // attached to something, and the difference between 429 and 202 is exactly
    // the enumeration oracle that this route's identical status, identical body
    // and unawaited send exist to prevent. So it is charged for every
    // well-formed request alike, whether or not the number belongs to anybody.
    if (!recoveryLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

    if (store.accountByRecoveryNumber(mac)) {
      const code = String(randomInt(0, 10 ** RECOVERY_CODE_DIGITS)).padStart(RECOVERY_CODE_DIGITS, '0');
      store.putRecoveryCode(mac, code, Date.now() + RECOVERY_CODE_TTL_MS);

      // Deliberately not awaited. Sending goes over the network to an SMS
      // gateway, and awaiting it here would make this route answer slowly for a
      // number that is attached and instantly for one that is not — the same
      // enumeration the identical status code and body exist to prevent, given
      // away by a stopwatch instead. Nothing in the response depends on the
      // send, so nothing is lost by returning first.
      void Promise.resolve(deliverRecoveryCode(parsed.data.phoneNumber, code)).catch((error: unknown) => {
        // The caller cannot be told — that would leak the same fact — so the
        // operator is, because a failing SMS gateway is otherwise invisible
        // until users start reporting that no code ever arrives.
        app.log.error({ err: error }, 'a recovery code could not be delivered');
      });
    }

    return reply.code(202).send();
  });

  /**
   * Finishes a recovery, binding the account to a new identity.
   *
   * The gateway never held the old private key and cannot return it, so this
   * gives back a handle and not a history — the conversations only ever existed
   * on the lost device. Every contact will see the safety number change, which
   * is the correct outcome and not a side effect worth hiding: whether the
   * person now holding this handle is a friend with a new phone or somebody who
   * obtained their SIM is precisely what that number is for.
   */
  app.post('/v1/recovery/complete', async (request, reply) => {
    const parsed = CompleteRecoveryRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });
    const body = parsed.data;

    const skew = Math.abs(Date.now() - body.timestamp);
    if (skew > 5 * 60 * 1000) return reply.code(400).send({ error: 'clock_skew' });

    const identityKey = parseIdentityKey(unb64(body.identityKey));
    if (!identityKey) return reply.code(400).send({ error: 'invalid_identity_key' });

    const { signature, ...unsigned } = body;
    if (!verifyPreKeySignature(identityKey, recoverySigningPayload(unsigned), unb64(signature))) {
      return reply.code(400).send({ error: 'invalid_signature' });
    }
    if (!verifyPreKeySignature(identityKey, unb64(body.signedPreKey.publicKey), unb64(body.signedPreKey.signature))) {
      return reply.code(400).send({ error: 'invalid_signed_prekey' });
    }
    if (!verifyPreKeySignature(identityKey, unb64(body.kyberPreKey.publicKey), unb64(body.kyberPreKey.signature))) {
      return reply.code(400).send({ error: 'invalid_kyber_prekey' });
    }

    // A bucket of its own, no longer the one /v1/recovery/start spends. Sharing
    // it meant a flood at the cheap unauthenticated half denied the half that
    // people only reach after a code has already been sent to them, which is the
    // worst possible thing to be able to switch off from the outside.
    //
    // Charged only once the three signatures over the recovery payload have
    // verified, because a signature is unforgeable work and that is the same
    // bargain registration makes: a request carrying no valid one is refused on
    // its merits and costs the gateway's budget nothing.
    if (!recoveryCompleteLimiter.tryConsume(GLOBAL)) {
      return reply.code(429).send({ error: 'slow_down' });
    }

    const mac = identity.numberMac(body.phoneNumber);
    if (!store.consumeRecoveryCode(mac, body.code, config.recoveryCodeAttempts)) {
      return reply.code(401).send({ error: 'bad_code' });
    }

    const aci = store.accountByRecoveryNumber(mac);
    if (!aci) return reply.code(404).send({ error: 'not_found' });

    const account = store.accountByAci(aci);
    if (!account) return reply.code(404).send({ error: 'not_found' });

    store.replaceIdentity(
      aci,
      unb64(body.identityKey),
      body.registrationId,
      {
        keyId: body.signedPreKey.keyId,
        publicKey: unb64(body.signedPreKey.publicKey),
        signature: unb64(body.signedPreKey.signature),
      },
      {
        keyId: body.kyberPreKey.keyId,
        publicKey: unb64(body.kyberPreKey.publicKey),
        signature: unb64(body.kyberPreKey.signature),
      },
      body.oneTimePreKeys.map((k) => ({ keyId: k.keyId, publicKey: unb64(k.publicKey) })),
    );

    return {
      aci: account.aci,
      // The hash, because that is all there is. A device recovering an account
      // learns which handle hash it owns and can confirm a name against it
      // offline; the gateway cannot tell it what the name was.
      usernameHash: b64(account.username_hash),
      bucketId: account.bucket_id,
      trustRoot: b64(identity.trustRootPublic.serialize()),
      powDifficulty: config.powDifficulty,
      // The account's own avatar seed. Returned so a device can draw what
      // everyone else sees of it without looking itself up in the directory,
      // which would be an odd request for a client to have to make.
      avatarSeed: b64(store.avatarSeed(account.aci) ?? Buffer.alloc(0)),
    };
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

    // Length first, because it is free and the next step is not. A sealed
    // request is exactly one size, and the proof of work that pays for a
    // submission is inside the ciphertext — so opening it is the first thing an
    // unauthenticated caller can make this server do, and it is a key
    // agreement. Anything that is not a candidate is refused before that.
    if (sealed.length !== OBLIVIOUS_SEALED_BYTES) {
      return reply.code(400).send({ error: 'invalid_request' });
    }

    // And a ceiling on the ones that are the right length, since a caller can
    // pad rubbish to any size they like. Every other unauthenticated route that
    // does public-key work has one of these; this route did not, which left the
    // only unmetered way to spend the gateway's CPU.
    //
    // The one place the rule the other routes follow — validate and prove work
    // first, charge the bucket last — cannot be applied, and the reason is worth
    // stating so nobody moves this line later on principle: the work that pays
    // for a submission is sealed inside the ciphertext, so there is nothing left
    // to check between the length and the key agreement itself. This ceiling has
    // to sit in front of the expensive step because it is the expensive step it
    // exists to ration. It is sized generously for exactly that reason, since
    // real traffic arrives here through relays and several may front one gateway.
    if (!obliviousLimiter.tryConsume(GLOBAL)) return reply.code(429).send({ error: 'slow_down' });

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
