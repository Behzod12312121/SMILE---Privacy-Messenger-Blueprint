import { resolve } from 'node:path';
import { DEFAULT_BUCKET_SIZE, REGISTRATION_POW_DIFFICULTY } from '@millygram/protocol';

export interface Bucket {
  capacity: number;
  refillPerSecond: number;
}

export interface RateLimits {
  /**
   * A ceiling on registrations for the whole gateway, not per address.
   *
   * Address-based rationing was the wrong shape for this market: Uzbek mobile
   * networks put whole subscriber bases behind a handful of public addresses,
   * so five signups per address meant five signups per carrier. Cost is
   * charged in proof of work instead — the same trade the submission path
   * already makes, and for the same reason: there is no identity to charge yet
   * and the address is not one. This limit is only a circuit breaker.
   */
  registration: Bucket;
  /**
   * A ceiling on tokens minted for the whole gateway, not per address. What
   * this protects is CPU, which is a global resource; who is spending it is
   * handled by [authPerAccount]. Charged only after a nonce has been redeemed
   * and a signature has verified, so an unsigned request cannot spend it.
   */
  auth: Bucket;
  /**
   * A ceiling on nonces issued for the whole gateway.
   *
   * Held apart from [auth] rather than shared with it. Sharing one bucket
   * between the two halves of login meant a flood aimed at either route closed
   * the other, and since the only place a usable nonce comes from is this one,
   * that was a way to stop everybody logging in without signing anything. It is
   * also what now bounds the signature verifications the auth route can be made
   * to perform, so the two limits are related rather than duplicated: no nonce,
   * no verification.
   */
  challenge: Bucket;
  /** Per account, once a signature has proved which account is asking. */
  authPerAccount: Bucket;
  /**
   * Per number, for starting a recovery. Harsh on purpose: this is the one
   * route that can hand somebody else's handle to whoever holds a SIM, so the
   * cost of trying is deliberately higher than the cost of asking politely.
   */
  recoveryPerNumber: Bucket;
  /**
   * Per calling account, for attaching a recovery number.
   *
   * Attaching refuses a number another account already holds, which makes it a
   * way to ask whether a given number is in use here. This is what makes asking
   * repeatedly expensive: a handful of tries, then a slow trickle, so probing a
   * list of numbers costs an account per few numbers rather than a loop.
   */
  attachNumber: Bucket;
  /**
   * A ceiling on recovery starts for the whole gateway. Small, because starting
   * a recovery is a rare thing to do and a cheap thing to abuse — which is
   * exactly why it must not be spendable by anything but a well-formed request.
   */
  recovery: Bucket;
  /**
   * A ceiling on recovery completions for the whole gateway, held apart from
   * [recovery].
   *
   * One bucket across both halves meant a flood at the unauthenticated start
   * route denied the completion route to the person who had already been sent a
   * code and was trying to use it — the one moment in this system where somebody
   * has lost their phone and is depending on it working.
   */
  recoveryComplete: Bucket;
  /**
   * Per calling account, for turning a typed handle into an account.
   *
   * Harsh on purpose, and affordable because re-contacting somebody already
   * known does not come through here — that path carries an account id the
   * device already holds and is rationed separately. Only genuine discovery
   * pays this, and genuine discovery is rare.
   */
  directory: Bucket;
  /** Per destination bucket. Never keyed on the sender; see the submit route. */
  inbound: Bucket;
  /**
   * A ceiling on oblivious submissions for the whole gateway. Opening one is a
   * key agreement and the work that pays for it is inside the ciphertext, so
   * this is the only limit that can apply before the expensive part.
   */
  oblivious: Bucket;
  /**
   * Per (caller, target) pair. Each bundle fetch consumes one of the target's
   * one-time prekeys, so an unthrottled caller can drain a victim's pool and
   * force every later session to open from a bundle without one.
   */
  preKeyBundlePerCaller: Bucket;
  /**
   * Per target, across all callers. Stops the same drain being mounted from
   * many accounts at once, and holds the drain rate below the rate at which a
   * client tops its pool back up.
   */
  preKeyBundlePerTarget: Bucket;
}

export interface ServerConfig {
  host: string;
  port: number;
  databasePath: string;
  /** Envelopes older than this are swept regardless of delivery. */
  envelopeTtlMs: number;
  /**
   * The most envelopes one bucket may be holding before submissions to it are
   * refused.
   *
   * Envelopes leave on the retention timer and never on delivery, because an
   * acknowledgement would tell the relay which of sixteen members an envelope
   * belonged to. A bucket's row count is therefore everything sent to it in
   * the last fourteen days, and the inbound limiter caps only the rate: over
   * that window it still integrates to about sixty thousand envelopes, half a
   * gigabyte for sixteen people. Nothing bounded the total, so disk grew
   * linearly with whatever CPU an attacker was willing to spend.
   *
   * At the ceiling, new submissions to that bucket are refused and nothing
   * already stored is touched. That is the deliberate half of the trade.
   * Refusing costs a sender a message they are told about and can send again;
   * making room by evicting would destroy an envelope the relay has already
   * accepted and whose recipient may never have collected it — and the relay
   * cannot tell which, by design. So the sixteen members' backlog is never the
   * thing that gives way. What is lost instead is new delivery to that bucket
   * until the oldest envelopes age out, which is a denial of service to the
   * same sixteen people, and it is why this number is generous rather than
   * tight: it is a backstop against disk exhaustion, not a second rate limit.
   *
   * Twenty thousand is roughly 175 MB a bucket and 11 MB a member — about a
   * dozen messages per member per day sustained for the entire retention
   * window, well above real conversation volume and well below what the
   * inbound limiter alone would permit.
   */
  maxEnvelopesPerBucket: number;
  /**
   * The most envelopes the whole relay may hold before it begins refusing the
   * buckets that are holding the most.
   *
   * The per-bucket ceiling bounds one mailbox; this one bounds the disk. Left
   * to the per-bucket limit alone, total storage is occupied buckets times
   * that limit, which grows with the account base and does nothing at all
   * about the measured attack — a flood spread thinly across many buckets
   * precisely so that no per-bucket limit ever binds, 4.67 GB a day for each
   * attacker core.
   *
   * Above this watermark a submission is admitted only while its bucket holds
   * less than an equal share of the ceiling. So the buckets doing the filling
   * are the ones refused, and a quiet bucket keeps receiving; storage settles
   * at the ceiling plus at most one envelope per bucket. A flat refusal would
   * have been three lines shorter and would have let whoever filled the disk
   * stop delivery for everybody, which is the attack rather than the defence.
   *
   * Four million envelopes is about 35 GB. This is the one limit here an
   * operator has to raise as their user base grows: a gateway whose ordinary
   * backlog approaches it will start refusing its busiest buckets, which is
   * the right answer for a disk that is full and the wrong one for a disk that
   * merely needs to be larger. Worth alerting on well before it is reached.
   */
  maxEnvelopesTotal: number;
  sweepIntervalMs: number;
  authTokenTtlMs: number;
  trustProxy: boolean;
  rateLimits: RateLimits;
  /** Accounts per delivery bucket, and so the size of the anonymity set. */
  bucketSize: number;
  /**
   * Leading zero bits required on a submission. Submission is anonymous, so the
   * relay cannot charge a sender by identity; it charges CPU instead. 16 costs
   * a sender roughly 150ms and a flooder the same per message.
   */
  powDifficulty: number;
  /**
   * How many bits of extra proof of work a bucket's submissions cost once its
   * inbound budget is being spent faster than it refills.
   *
   * Delivery is per-bucket and submission is anonymous by design, so there is
   * no sender to key a limit on: the inbound budget is shared by all sixteen
   * members and one flooder can spend the lot. Bucket ids are sequential and
   * are handed out by the directory, so picking a victim is free. Measured, a
   * bucket refills at 0.05/s, so holding one empty costs one message every
   * twenty seconds - about 0.78% of a core at difficulty 16, which denies
   * inbound delivery to sixteen people for essentially nothing.
   *
   * The budget therefore sets a price rather than only a verdict. As it drains,
   * required work rises by up to this many bits, so holding a bucket empty
   * costs 2^this times what it did. At the default of 6 that is 64x, turning
   * one core against a thousand buckets into one core against sixteen.
   *
   * It is not free: an honest sender to a bucket somebody is flooding pays the
   * same higher price, and the required difficulty travels in the rejection, so
   * it also tells the caller roughly how busy a bucket is. Both are preferable
   * to the alternative, which is that the sixteen simply stop receiving.
   */
  inboundPowEscalationMax: number;
  /** How many guesses a recovery code survives before it is thrown away. */
  recoveryCodeAttempts: number;
  /** Leading zero bits a registration must carry. See the protocol constant. */
  registrationPowDifficulty: number;
  /**
   * How much undelivered traffic may queue for one delivery socket before it is
   * dropped. Writing to a peer that has stopped reading queues in the relay's
   * memory rather than failing.
   */
  maxSocketBufferBytes: number;
  /**
   * Whether to refuse auth from a device whose self-reported environment
   * signal names a blocked flag. Off by default: the signal is a defeatable
   * self-report, so this only ever turns away the honest client that admitted
   * a rooted or hooked environment, while the attacker who reports "clean"
   * walks straight in. Turning it on is also what decides whether a refusal is
   * written down against the account it refused: with enforcement off nothing
   * about who is ever logged, because a note that this account was online at
   * this minute from a rooted handset is precisely the record the rest of this
   * gateway is built not to keep. See [[AuthRequest.environment]] and the auth
   * route.
   */
  refuseTamperedEnvironments: boolean;
  /** Which environment flags, if any, refuseTamperedEnvironments acts on. */
  blockedEnvironmentFlags: string[];
}

/**
 * Bits of extra work an empty bucket charges. Exported so a test asserts the
 * price the gateway actually sets rather than a number copied beside it.
 */
export const DEFAULT_INBOUND_POW_ESCALATION = 6;

export const DEFAULT_RATE_LIMITS: RateLimits = {
  // Sized for the whole gateway. Generous, because the real price of a
  // registration is the work attached to it; this only stops a flood from
  // becoming a database.
  registration: { capacity: 200, refillPerSecond: 2 },
  auth: { capacity: 2000, refillPerSecond: 50 },
  // The same shape as auth, because in normal use the two routes are called in
  // lockstep — one nonce fetched, one token minted. They are separate buckets so
  // that a flood at one cannot empty the other, not because the traffic differs.
  challenge: { capacity: 2000, refillPerSecond: 50 },
  // A single account has no reason to mint tokens faster than this, and a
  // token lasts fifteen minutes.
  authPerAccount: { capacity: 20, refillPerSecond: 1 / 30 },

  // Three codes an hour for one number, and a slow refill. Somebody recovering
  // a lost phone needs one; somebody working through numbers needs many.
  recoveryPerNumber: { capacity: 3, refillPerSecond: 1 / 1200 },
  // Nobody sets their own number five times in an hour; a prober wants
  // thousands.
  attachNumber: { capacity: 5, refillPerSecond: 1 / 900 },
  recovery: { capacity: 60, refillPerSecond: 1 / 30 },
  recoveryComplete: { capacity: 60, refillPerSecond: 1 / 30 },
  // Twelve to begin with, then one back every ten minutes. Somebody adding the
  // people they know in one sitting is comfortably inside that; somebody
  // sweeping the namespace manages about fifty a day, against a space of ten
  // thousand discriminators multiplied by every nickname worth guessing.
  directory: { capacity: 12, refillPerSecond: 1 / 600 },

  /**
   * Every member of a bucket downloads every envelope sent to it, so this
   * limit is multiplied by the bucket size in bandwidth terms. At 8 KB an
   * envelope and sixteen members, the earlier 2/s allowed roughly 1.4 GB per
   * member per day — unusable on the mobile data this app exists to run on.
   * Three a minute is about 35 MB a day per member and still well above real
   * conversation volume.
   */
  inbound: { capacity: 60, refillPerSecond: 0.05 },

  // Sized for the whole gateway rather than any caller, since a submission is
  // anonymous by construction. Generous: real traffic arrives here through
  // relays, and several of them may front one gateway.
  oblivious: { capacity: 2000, refillPerSecond: 500 },

  preKeyBundlePerCaller: { capacity: 5, refillPerSecond: 1 / 600 },
  preKeyBundlePerTarget: { capacity: 12, refillPerSecond: 1 / 300 },
};

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

export function loadConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    host: process.env.MG_HOST ?? '127.0.0.1',
    port: intFromEnv('MG_PORT', 8443),
    databasePath: resolve(process.env.MG_DB ?? 'millygram-server.db'),
    envelopeTtlMs: intFromEnv('MG_ENVELOPE_TTL_MS', 14 * 24 * 60 * 60 * 1000),
    maxEnvelopesPerBucket: intFromEnv('MG_MAX_ENVELOPES_PER_BUCKET', 20_000),
    maxEnvelopesTotal: intFromEnv('MG_MAX_ENVELOPES_TOTAL', 4_000_000),
    sweepIntervalMs: intFromEnv('MG_SWEEP_INTERVAL_MS', 60 * 60 * 1000),
    authTokenTtlMs: intFromEnv('MG_AUTH_TTL_MS', 15 * 60 * 1000),
    trustProxy: process.env.MG_TRUST_PROXY === '1',
    /**
     * The registration circuit breaker is the one limit an operator needs to
     * move: a migration or an end-to-end suite creates accounts far faster
     * than people do, and a 429 there is not a security signal. The price of a
     * registration is its proof of work, tuned separately by
     * MG_REGISTRATION_POW_DIFFICULTY.
     *
     * Everything else stays fixed, widened by configuration rather than by
     * editing the defaults.
     */
    rateLimits: {
      ...DEFAULT_RATE_LIMITS,
      registration: {
        capacity: intFromEnv('MG_REGISTRATION_CAPACITY', DEFAULT_RATE_LIMITS.registration.capacity),
        refillPerSecond:
          1 /
          intFromEnv(
            'MG_REGISTRATION_INTERVAL_SECONDS',
            1 / DEFAULT_RATE_LIMITS.registration.refillPerSecond,
          ),
      },
    },
    bucketSize: intFromEnv('MG_BUCKET_SIZE', DEFAULT_BUCKET_SIZE),
    powDifficulty: intFromEnv('MG_POW_DIFFICULTY', 16),
    inboundPowEscalationMax: intFromEnv('MG_INBOUND_POW_ESCALATION_MAX', DEFAULT_INBOUND_POW_ESCALATION),
    registrationPowDifficulty: intFromEnv(
      'MG_REGISTRATION_POW_DIFFICULTY',
      REGISTRATION_POW_DIFFICULTY,
    ),
    maxSocketBufferBytes: intFromEnv('MG_MAX_SOCKET_BUFFER_BYTES', 512 * 1024),
    refuseTamperedEnvironments: process.env.MG_REFUSE_TAMPERED === '1',
    blockedEnvironmentFlags: (process.env.MG_BLOCKED_ENV_FLAGS ?? 'hook,debugger')
      .split(',')
      .map((f) => f.trim())
      .filter((f) => f.length > 0),
    recoveryCodeAttempts: intFromEnv('MG_RECOVERY_CODE_ATTEMPTS', 5),
    ...overrides,
  };
}
