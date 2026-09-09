interface Bucket {
  tokens: number;
  updatedAt: number;
}

/**
 * A token bucket that keeps nothing but a counter and a timestamp per key.
 * Callers choose the key deliberately: sealed-sender traffic is limited by
 * destination, never by source, so that throttling never becomes a record of
 * who was talking to whom.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly capacity: number,
    private readonly refillPerSecond: number,
  ) {}

  tryConsume(key: string, cost = 1, now = Date.now()): boolean {
    const bucket = this.buckets.get(key);
    if (!bucket) {
      if (cost > this.capacity) return false;
      this.buckets.set(key, { tokens: this.capacity - cost, updatedAt: now });
      return true;
    }

    const refilled = Math.min(
      this.capacity,
      bucket.tokens + ((now - bucket.updatedAt) / 1000) * this.refillPerSecond,
    );
    if (refilled < cost) {
      bucket.tokens = refilled;
      bucket.updatedAt = now;
      return false;
    }

    bucket.tokens = refilled - cost;
    bucket.updatedAt = now;
    return true;
  }

  /**
   * How many tokens a key has right now, without spending one.
   *
   * Used to price a submission rather than to admit it: an empty bucket is the
   * signal that somebody is filling it, and the answer to that is to make the
   * next submission cost more, not only to refuse it. Reading must not consume,
   * or asking the price would itself be a way to drain the budget.
   */
  remaining(key: string, now = Date.now()): number {
    const bucket = this.buckets.get(key);
    if (!bucket) return this.capacity;
    return Math.min(this.capacity, bucket.tokens + ((now - bucket.updatedAt) / 1000) * this.refillPerSecond);
  }

  /** Drops buckets that have fully refilled, so idle keys leave no trace. */
  sweep(now = Date.now()): void {
    const fullAfterMs = (this.capacity / this.refillPerSecond) * 1000;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > fullAfterMs) this.buckets.delete(key);
    }
  }

  get size(): number {
    return this.buckets.size;
  }
}
