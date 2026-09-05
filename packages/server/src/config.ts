import { resolve } from 'node:path';
import { DEFAULT_BUCKET_SIZE } from '@millygram/protocol';

export interface Bucket {
  capacity: number;
  refillPerSecond: number;
}

export interface RateLimits {
  /** Per source address. Deliberately harsh: nobody registers twice a minute. */
  registration: Bucket;
  /** Per source address. */
  auth: Bucket;
  /** Per calling account, so username lookups cannot be used to enumerate. */
  directory: Bucket;
  /** Per destination bucket. Never keyed on the sender; see the submit route. */
  inbound: Bucket;
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
}

export const DEFAULT_RATE_LIMITS: RateLimits = {
  registration: { capacity: 5, refillPerSecond: 1 / 60 },
  auth: { capacity: 30, refillPerSecond: 1 / 10 },
  directory: { capacity: 20, refillPerSecond: 1 / 30 },

  /**
   * Every member of a bucket downloads every envelope sent to it, so this
   * limit is multiplied by the bucket size in bandwidth terms. At 8 KB an
   * envelope and sixteen members, the earlier 2/s allowed roughly 1.4 GB per
   * member per day — unusable on the mobile data this app exists to run on.
   * Three a minute is about 35 MB a day per member and still well above real
   * conversation volume.
   */
  inbound: { capacity: 60, refillPerSecond: 0.05 },

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
    sweepIntervalMs: intFromEnv('MG_SWEEP_INTERVAL_MS', 60 * 60 * 1000),
    authTokenTtlMs: intFromEnv('MG_AUTH_TTL_MS', 15 * 60 * 1000),
    trustProxy: process.env.MG_TRUST_PROXY === '1',
    rateLimits: DEFAULT_RATE_LIMITS,
    bucketSize: intFromEnv('MG_BUCKET_SIZE', DEFAULT_BUCKET_SIZE),
    powDifficulty: intFromEnv('MG_POW_DIFFICULTY', 16),
    ...overrides,
  };
}
