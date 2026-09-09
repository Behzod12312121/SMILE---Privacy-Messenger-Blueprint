import { timingSafeEqual } from 'node:crypto';
import Database from 'better-sqlite3';
import { AVATAR_SEED_BYTES, usernameHash } from '@millygram/protocol';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

/**
 * The schema is the security claim.
 *
 * There is no column for message plaintext, no column for a sender, no phone
 * number, and no presence. Envelopes are addressed to a bucket shared by many
 * accounts, so there is no column for a recipient either: the operator can say
 * that one of sixteen people received something, and nothing more precise.
 * A subpoena served on this database cannot produce more than that.
 */
const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS server_state (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  aci             TEXT PRIMARY KEY,
  -- The 32-byte hash of the handle, never the handle. A gateway holding
  -- plaintext names holds a list somebody can be made to hand over; this one
  -- cannot produce a name it has never been told.
  username_hash   BLOB NOT NULL UNIQUE,
  device_id       INTEGER NOT NULL,
  bucket_id       INTEGER NOT NULL,
  registration_id INTEGER NOT NULL,
  identity_key    BLOB NOT NULL,
  created_at      INTEGER NOT NULL,
  avatar_seed     BLOB
);

CREATE INDEX IF NOT EXISTS accounts_bucket ON accounts (bucket_id);

/*
 * Numbers attached for recovery, and never the numbers themselves.
 *
 * A phone number has about as much entropy as a short word, so a plain hash of
 * one is a lookup table away from the original. What is stored is a keyed hash
 * under a secret this server holds, which makes the column useless to anybody
 * who takes only the database — and still readable to anybody who takes the key
 * as well. That is the honest ceiling: a gateway able to answer "which account
 * has this number" is a gateway holding that link, however it is spelled.
 *
 * Separate table rather than a column, so an account that never attaches one
 * has no row here at all.
 */
CREATE TABLE IF NOT EXISTS recovery_numbers (
  number_mac  BLOB PRIMARY KEY,
  aci         TEXT NOT NULL UNIQUE REFERENCES accounts(aci) ON DELETE CASCADE,
  attached_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  number_mac BLOB PRIMARY KEY,
  code       TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS signed_prekeys (
  aci        TEXT PRIMARY KEY REFERENCES accounts(aci) ON DELETE CASCADE,
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  signature  BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS kyber_prekeys (
  aci        TEXT PRIMARY KEY REFERENCES accounts(aci) ON DELETE CASCADE,
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  signature  BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
  aci        TEXT NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
  key_id     INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  PRIMARY KEY (aci, key_id)
);

CREATE TABLE IF NOT EXISTS envelopes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket_id  INTEGER NOT NULL,
  content    BLOB NOT NULL,
  arrived_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS envelopes_bucket ON envelopes (bucket_id, seq);

CREATE TABLE IF NOT EXISTS auth_challenges (
  nonce      BLOB PRIMARY KEY,
  aci        TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Replay defence for anonymous submission. Holds only a digest of the
-- ciphertext, which reveals nothing the relay did not already hold, and is
-- swept on the same schedule as the envelopes themselves.
CREATE TABLE IF NOT EXISTS submission_digests (
  digest  BLOB PRIMARY KEY,
  seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS submission_digests_seen ON submission_digests (seen_at);
`;

export interface AccountRow {
  aci: string;
  username_hash: Buffer;
  device_id: number;
  bucket_id: number;
  registration_id: number;
  identity_key: Buffer;
  created_at: number;
}

export interface PreKeyRow {
  key_id: number;
  public_key: Buffer;
  signature: Buffer;
}

export interface OneTimePreKeyRow {
  key_id: number;
  public_key: Buffer;
}

export interface EnvelopeRow {
  seq: number;
  bucket_id: number;
  content: Buffer;
  arrived_at: number;
}

export interface NewAccount {
  usernameHash: Uint8Array;
  deviceId: number;
  registrationId: number;
  identityKey: Uint8Array;
  signedPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array };
  kyberPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKeys: { keyId: number; publicKey: Uint8Array }[];
}

export class Store {
  private readonly db: Database.Database;

  /**
   * How many envelopes each bucket is holding, and how many are held in all.
   *
   * Counted in memory rather than queried. The storage ceilings are consulted
   * on every submission that has already paid its work, and `SELECT COUNT(*)`
   * over a table this design allows to reach millions of rows is a scan; a
   * number incremented on insert and rebuilt after each sweep costs nothing
   * and is exact for the one process that owns this file. A second writer
   * against the same database would desync it, which is why there is only
   * ever one — `startServer` opens the store, and nothing else does.
   */
  private readonly envelopesByBucket = new Map<number, number>();
  private envelopesHeld = 0;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.exec(SCHEMA);
    this.addAvatarSeedColumn();
    this.replacePlaintextUsernames();
    this.recountEnvelopes();
  }

  /**
   * Rebuilds the in-memory envelope counts from what is actually stored.
   *
   * Run at startup, so a relay that restarts with a full database enforces its
   * ceilings from the first submission rather than from zero, and again after
   * each sweep, which deletes across every bucket at once.
   */
  private recountEnvelopes(): void {
    this.envelopesByBucket.clear();
    this.envelopesHeld = 0;
    const rows = this.db
      .prepare('SELECT bucket_id, COUNT(*) AS n FROM envelopes GROUP BY bucket_id')
      .all() as { bucket_id: number; n: number }[];
    for (const row of rows) {
      this.envelopesByBucket.set(row.bucket_id, row.n);
      this.envelopesHeld += row.n;
    }
  }

  /**
   * What the storage ceilings are measured against: what this bucket holds,
   * what the relay holds, and how many buckets are holding anything at all.
   *
   * One call and three map reads, because it runs on the hot path of every
   * paid-for submission.
   */
  envelopeLoad(bucketId: number): { inBucket: number; total: number; buckets: number } {
    return {
      inBucket: this.envelopesByBucket.get(bucketId) ?? 0,
      total: this.envelopesHeld,
      buckets: this.envelopesByBucket.size,
    };
  }

  close(): void {
    this.db.close();
  }

  getState(key: string): Buffer | null {
    const row = this.db.prepare('SELECT value FROM server_state WHERE key = ?').get(key) as
      | { value: Buffer }
      | undefined;
    return row?.value ?? null;
  }

  putState(key: string, value: Uint8Array): void {
    this.db
      .prepare('INSERT INTO server_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, Buffer.from(value));
  }

  accountByUsernameHash(usernameHash: Uint8Array): AccountRow | null {
    return (
      (this.db
        .prepare('SELECT * FROM accounts WHERE username_hash = ?')
        .get(Buffer.from(usernameHash)) as AccountRow) ?? null
    );
  }

  accountByAci(aci: string): AccountRow | null {
    return (this.db.prepare('SELECT * FROM accounts WHERE aci = ?').get(aci) as AccountRow) ?? null;
  }

  /**
   * Buckets fill in order so that every closed bucket holds exactly
   * `bucketSize` accounts. Only the newest bucket is ever partial, and it is
   * the only one where the anonymity set is smaller than advertised.
   */
  /**
   * Converts a database that still holds plaintext handles, and then stops
   * holding them.
   *
   * The column existed for as long as the gateway resolved names itself. It
   * cannot now: a handle arrives as a hash and a proof, and the gateway has no
   * way to compute the one from the other. Anything already stored that is a
   * well-formed handle is converted in place; anything that is not — a bare
   * nickname from before handles carried digits — cannot be, and its account
   * keeps working under its account id while becoming unfindable by name until
   * it registers one again.
   *
   * The plaintext column is dropped rather than left empty. A name the gateway
   * no longer needs is a name it should not still be able to be asked for, and
   * an emptied column is one careless migration away from being repopulated.
   */
  private replacePlaintextUsernames(): void {
    const columns = this.db.prepare('PRAGMA table_info(accounts)').all() as { name: string }[];
    if (!columns.some((c) => c.name === 'username')) return;

    if (!columns.some((c) => c.name === 'username_hash')) {
      this.db.prepare('ALTER TABLE accounts ADD COLUMN username_hash BLOB').run();
    }

    const rows = this.db
      .prepare('SELECT aci, username FROM accounts WHERE username_hash IS NULL')
      .all() as { aci: string; username: string }[];
    const write = this.db.prepare('UPDATE accounts SET username_hash = ? WHERE aci = ?');
    let orphaned = 0;
    for (const row of rows) {
      try {
        write.run(Buffer.from(usernameHash(row.username)), row.aci);
      } catch {
        // Not a handle libsignal recognises, so there is nothing to convert.
        orphaned += 1;
      }
    }

    // An account whose handle could not be converted still has to satisfy the
    // new column, which is NOT NULL. It gets random bytes: unique, so the index
    // holds, and matching nothing anybody can hash, so the account keeps
    // receiving under its account id while staying unfindable by name — which
    // is exactly what the comment above promises.
    const unconvertible = this.db
      .prepare('SELECT aci FROM accounts WHERE username_hash IS NULL')
      .all() as { aci: string }[];
    for (const row of unconvertible) {
      write.run(randomBytes(32), row.aci);
    }

    // Rebuilt rather than altered. SQLite refuses to DROP a column carrying a
    // UNIQUE constraint — `username` was declared `NOT NULL UNIQUE`, so the
    // drop fails with "cannot drop UNIQUE column" and takes the gateway down on
    // every start. That is invisible on a fresh database, where this migration
    // never runs at all, and fatal on every database that has ever held an
    // account. Copying into a table that simply lacks the column is the way
    // SQLite documents for this, and it is not conditional on the constraint.
    //
    // Foreign keys are suspended for the swap: other tables reference
    // accounts(aci), and dropping the old table with them enforced would fail.
    // Their clauses resolve to the new table once it takes the name.
    const hadForeignKeys = this.db.pragma('foreign_keys', { simple: true }) === 1;
    if (hadForeignKeys) this.db.pragma('foreign_keys = OFF');
    try {
      this.db.exec(`
        CREATE TABLE accounts_rebuilt (
          aci             TEXT PRIMARY KEY,
          username_hash   BLOB NOT NULL UNIQUE,
          device_id       INTEGER NOT NULL,
          bucket_id       INTEGER NOT NULL,
          registration_id INTEGER NOT NULL,
          identity_key    BLOB NOT NULL,
          created_at      INTEGER NOT NULL,
          avatar_seed     BLOB
        );
        INSERT INTO accounts_rebuilt
          (aci, username_hash, device_id, bucket_id, registration_id, identity_key, created_at, avatar_seed)
          SELECT aci, username_hash, device_id, bucket_id, registration_id, identity_key, created_at, avatar_seed
          FROM accounts;
        DROP TABLE accounts;
        ALTER TABLE accounts_rebuilt RENAME TO accounts;
        CREATE INDEX IF NOT EXISTS accounts_bucket ON accounts (bucket_id);
      `);
    } finally {
      if (hadForeignKeys) this.db.pragma('foreign_keys = ON');
    }
    if (orphaned > 0) {
      // Not thrown: an account that cannot be found by name still receives, and
      // refusing to start would take the whole gateway down over it.
      console.warn(`millygram: ${orphaned} account(s) had no convertible handle and are unfindable by name`);
    }
  }

  /**
   * Adds the avatar seed to a database created before it existed.
   *
   * Additive and nullable, so an older gateway's accounts keep working and get
   * a seed the first time one is asked for. SQLite has no IF NOT EXISTS for
   * columns, so the duplicate error is the check.
   */
  private addAvatarSeedColumn(): void {
    try {
      this.db.prepare('ALTER TABLE accounts ADD COLUMN avatar_seed BLOB').run();
    } catch {
      // Already there.
    }
  }

  /**
   * The eight bytes an account's avatar is drawn from.
   *
   * Generated here and nowhere else. The account holder never supplies it, so
   * there is no value a client can choose in order to render something it
   * wants other people to see — the whole point of not letting anybody upload
   * a picture. Backfilled on read for accounts that predate the column.
   */
  avatarSeed(aci: string): Buffer | null {
    const row = this.db
      .prepare('SELECT avatar_seed FROM accounts WHERE aci = ?')
      .get(aci) as { avatar_seed: Buffer | null } | undefined;
    if (!row) return null;
    if (row.avatar_seed) return row.avatar_seed;

    const seed = randomBytes(AVATAR_SEED_BYTES);
    this.db.prepare('UPDATE accounts SET avatar_seed = ? WHERE aci = ?').run(seed, aci);
    return seed;
  }

  /**
   * Creates an account, choosing its discriminator here rather than taking one.
   *
   * The digits are drawn at random inside the same transaction that inserts the
   * row, so two people registering the same nickname at the same moment cannot
   * both be handed the same handle — the UNIQUE index on username is what
   * actually decides, and this only has to find a free slot to offer it.
   *
   * Sixty-four draws rather than a scan of what is taken. A scan would need the
   * nickname stored separately from the handle, and the only case where random
   * draws struggle is a nickname already about nine-tenths full, which at ten
   * thousand slots means nine thousand people who chose the same name. That is
   * not a state this directory reaches, and if it ever did, refusing the name is
   * the right answer anyway.
   *
   * Null when no free slot was found, which the route answers as a taken name.
   */
  createAccount(
    account: NewAccount,
    bucketSize: number,
  ): { aci: string; bucketId: number } | null {
    const aci = randomUUID();
    const now = Date.now();

    return this.db.transaction(() => {
      // The client chose the discriminator and proved it knows the name behind
      // the hash; all that is left here is whether the hash is already claimed.
      const usernameHash = Buffer.from(account.usernameHash);
      if (this.db.prepare('SELECT 1 FROM accounts WHERE username_hash = ?').get(usernameHash)) {
        return null;
      }

      const { total } = this.db.prepare('SELECT COUNT(*) AS total FROM accounts').get() as { total: number };
      const bucketId = Math.floor(total / bucketSize);

      this.db
        .prepare(
          `INSERT INTO accounts (aci, username_hash, device_id, bucket_id, registration_id, identity_key, created_at, avatar_seed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          aci,
          usernameHash,
          account.deviceId,
          bucketId,
          account.registrationId,
          Buffer.from(account.identityKey),
          now,
          randomBytes(AVATAR_SEED_BYTES),
        );

      this.writeSignedPreKey(aci, account.signedPreKey);
      this.writeKyberPreKey(aci, account.kyberPreKey);
      this.addOneTimePreKeys(aci, account.oneTimePreKeys);

      return { aci, bucketId };
    })();
  }

  bucketMembers(bucketId: number): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM accounts WHERE bucket_id = ?').get(bucketId) as {
      n: number;
    };
    return row.n;
  }

  writeSignedPreKey(aci: string, key: { keyId: number; publicKey: Uint8Array; signature: Uint8Array }): void {
    this.db
      .prepare(
        `INSERT INTO signed_prekeys (aci, key_id, public_key, signature) VALUES (?, ?, ?, ?)
         ON CONFLICT(aci) DO UPDATE SET key_id = excluded.key_id, public_key = excluded.public_key, signature = excluded.signature`,
      )
      .run(aci, key.keyId, Buffer.from(key.publicKey), Buffer.from(key.signature));
  }

  writeKyberPreKey(aci: string, key: { keyId: number; publicKey: Uint8Array; signature: Uint8Array }): void {
    this.db
      .prepare(
        `INSERT INTO kyber_prekeys (aci, key_id, public_key, signature) VALUES (?, ?, ?, ?)
         ON CONFLICT(aci) DO UPDATE SET key_id = excluded.key_id, public_key = excluded.public_key, signature = excluded.signature`,
      )
      .run(aci, key.keyId, Buffer.from(key.publicKey), Buffer.from(key.signature));
  }

  addOneTimePreKeys(aci: string, keys: { keyId: number; publicKey: Uint8Array }[]): void {
    const insert = this.db.prepare(
      'INSERT OR REPLACE INTO one_time_prekeys (aci, key_id, public_key) VALUES (?, ?, ?)',
    );
    this.db.transaction(() => {
      for (const key of keys) insert.run(aci, key.keyId, Buffer.from(key.publicKey));
    })();
  }

  signedPreKey(aci: string): PreKeyRow | null {
    return (this.db.prepare('SELECT key_id, public_key, signature FROM signed_prekeys WHERE aci = ?').get(aci) as PreKeyRow) ?? null;
  }

  kyberPreKey(aci: string): PreKeyRow | null {
    return (this.db.prepare('SELECT key_id, public_key, signature FROM kyber_prekeys WHERE aci = ?').get(aci) as PreKeyRow) ?? null;
  }

  /** One-time prekeys are single use: taking one removes it in the same transaction. */
  takeOneTimePreKey(aci: string): OneTimePreKeyRow | null {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT key_id, public_key FROM one_time_prekeys WHERE aci = ? ORDER BY key_id LIMIT 1')
        .get(aci) as OneTimePreKeyRow | undefined;
      if (!row) return null;
      this.db.prepare('DELETE FROM one_time_prekeys WHERE aci = ? AND key_id = ?').run(aci, row.key_id);
      return row;
    })();
  }

  countOneTimePreKeys(aci: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM one_time_prekeys WHERE aci = ?').get(aci) as { n: number };
    return row.n;
  }

  enqueue(bucketId: number, content: Uint8Array): EnvelopeRow {
    const info = this.db
      .prepare('INSERT INTO envelopes (bucket_id, content, arrived_at) VALUES (?, ?, ?)')
      .run(bucketId, Buffer.from(content), Date.now());
    this.envelopesByBucket.set(bucketId, (this.envelopesByBucket.get(bucketId) ?? 0) + 1);
    this.envelopesHeld += 1;
    return this.db.prepare('SELECT * FROM envelopes WHERE seq = ?').get(info.lastInsertRowid) as EnvelopeRow;
  }

  /**
   * Everything the bucket has received since the caller last looked. Members
   * take the whole bucket and discard what they cannot decrypt; the relay never
   * learns which envelopes were theirs.
   */
  since(bucketId: number, cursor: number, limit = 500): EnvelopeRow[] {
    return this.db
      .prepare('SELECT * FROM envelopes WHERE bucket_id = ? AND seq > ? ORDER BY seq LIMIT ?')
      .all(bucketId, cursor, limit) as EnvelopeRow[];
  }

  /**
   * Records a submission and reports whether it is new. Returns false for a
   * replay, which is how the relay refuses to fan the same envelope out to a
   * bucket twice.
   *
   * Only a digest is kept. A legitimate resend never collides here because
   * every envelope carries fresh random padding and a fresh ratchet output, so
   * two genuine submissions cannot produce the same bytes.
   */
  rememberSubmission(content: Uint8Array): boolean {
    const digest = createHash('sha256').update(content).digest();
    const result = this.db
      .prepare('INSERT OR IGNORE INTO submission_digests (digest, seen_at) VALUES (?, ?)')
      .run(digest, Date.now());
    return result.changes > 0;
  }

  /**
   * Whether these exact bytes have been submitted before, writing nothing.
   *
   * Split out of [rememberSubmission] so the submit path can ask the replay
   * question before it charges the inbound limiter and record the answer only
   * after. The order is not cosmetic in either direction: asking first is what
   * stops a replayed submission — which carries no fresh proof of work, only a
   * copy of somebody else's — from spending a token out of a bucket's shared
   * budget before anything notices what it is. Recording after is what stops
   * the digest table growing at the full work rate for submissions the limiter
   * refuses; a row is now written only for an envelope that was actually
   * stored, so this table can never outgrow the one it protects.
   *
   * A read against the primary key, so it is a single index probe and no disk
   * is written for a submission that never lands.
   */
  hasSubmission(content: Uint8Array): boolean {
    const digest = createHash('sha256').update(content).digest();
    return this.db.prepare('SELECT 1 FROM submission_digests WHERE digest = ?').get(digest) !== undefined;
  }

  /**
   * Envelopes are removed on a timer, never on acknowledgement. An ack would
   * tell the relay which bucket member a given envelope belonged to.
   */
  sweepEnvelopes(olderThanMs: number): number {
    const cutoff = Date.now() - olderThanMs;
    // Digests are swept on the same cutoff. A replay of something older than
    // the envelope retention window has nothing left to duplicate.
    this.db.prepare('DELETE FROM submission_digests WHERE seen_at < ?').run(cutoff);
    const removed = this.db.prepare('DELETE FROM envelopes WHERE arrived_at < ?').run(cutoff).changes;
    // The delete spans every bucket, so the counts the storage ceilings read
    // are rebuilt rather than adjusted. Once an hour, and only when something
    // actually left.
    if (removed > 0) this.recountEnvelopes();
    return removed;
  }

  putChallenge(nonce: Uint8Array, aci: string, expiresAt: number): void {
    this.db
      .prepare('INSERT OR REPLACE INTO auth_challenges (nonce, aci, expires_at) VALUES (?, ?, ?)')
      .run(Buffer.from(nonce), aci, expiresAt);
  }

  /** Consumes the challenge whether or not it was valid, so it is strictly single use. */
  consumeChallenge(nonce: Uint8Array, aci: string): boolean {
    return this.db.transaction(() => {
      const row = this.db.prepare('SELECT aci, expires_at FROM auth_challenges WHERE nonce = ?').get(Buffer.from(nonce)) as
        | { aci: string; expires_at: number }
        | undefined;
      this.db.prepare('DELETE FROM auth_challenges WHERE nonce = ?').run(Buffer.from(nonce));
      if (!row) return false;
      return row.aci === aci && row.expires_at > Date.now();
    })();
  }

  /** Attaches a number to an account, replacing whatever that account had. */
  /**
   * Binds a number to an account, unless another account already holds it.
   *
   * Refusing is the whole point. Nothing here proves the caller can receive SMS
   * at this number — that is only checked at recovery, which is the trade this
   * feature makes for not asking anyone to verify a number at signup. The
   * consequence is that whoever claims a number first must keep it: an upsert
   * would let anybody type a stranger's number into their own account and take
   * over the row, and the victim would find out only on the day they lost their
   * phone and tried to recover.
   *
   * Returns false when the number belongs to somebody else. Re-attaching a
   * number the caller already holds succeeds, so a user correcting a typo in
   * their own entry is not fighting this rule.
   */
  attachRecoveryNumber(numberMac: Uint8Array, aci: string, now = Date.now()): boolean {
    return this.db.transaction(() => {
      const key = Buffer.from(numberMac);
      const holder = this.db
        .prepare('SELECT aci FROM recovery_numbers WHERE number_mac = ?')
        .get(key) as { aci: string } | undefined;
      if (holder && holder.aci !== aci) return false;

      this.db.prepare('DELETE FROM recovery_numbers WHERE aci = ?').run(aci);
      this.db
        .prepare('INSERT INTO recovery_numbers (number_mac, aci, attached_at) VALUES (?, ?, ?)')
        .run(key, aci, now);
      return true;
    })();
  }

  detachRecoveryNumber(aci: string): void {
    this.db.prepare('DELETE FROM recovery_numbers WHERE aci = ?').run(aci);
  }

  hasRecoveryNumber(aci: string): boolean {
    return this.db.prepare('SELECT 1 FROM recovery_numbers WHERE aci = ?').get(aci) !== undefined;
  }

  accountByRecoveryNumber(numberMac: Uint8Array): string | null {
    const row = this.db
      .prepare('SELECT aci FROM recovery_numbers WHERE number_mac = ?')
      .get(Buffer.from(numberMac)) as { aci: string } | undefined;
    return row?.aci ?? null;
  }

  putRecoveryCode(numberMac: Uint8Array, code: string, expiresAt: number): void {
    this.db
      .prepare(
        'INSERT INTO recovery_codes (number_mac, code, expires_at, attempts) VALUES (?, ?, ?, 0) ' +
          'ON CONFLICT(number_mac) DO UPDATE SET code = excluded.code, expires_at = excluded.expires_at, attempts = 0',
      )
      .run(Buffer.from(numberMac), code, expiresAt);
  }

  /**
   * Spends one guess at a recovery code.
   *
   * The attempt is counted whether or not it was right, and the row is dropped
   * once too many have been spent, so a six-digit code cannot be walked
   * through. A correct answer removes it too: one code, one use.
   */
  consumeRecoveryCode(numberMac: Uint8Array, code: string, maxAttempts: number, now = Date.now()): boolean {
    return this.db.transaction(() => {
      const key = Buffer.from(numberMac);
      const row = this.db
        .prepare('SELECT code, expires_at, attempts FROM recovery_codes WHERE number_mac = ?')
        .get(key) as { code: string; expires_at: number; attempts: number } | undefined;
      if (!row) return false;

      if (row.expires_at <= now || row.attempts + 1 >= maxAttempts) {
        this.db.prepare('DELETE FROM recovery_codes WHERE number_mac = ?').run(key);
        if (row.expires_at <= now) return false;
      } else {
        this.db.prepare('UPDATE recovery_codes SET attempts = attempts + 1 WHERE number_mac = ?').run(key);
      }

      const matches = row.code.length === code.length && timingSafeEqual(Buffer.from(row.code), Buffer.from(code));
      if (matches) this.db.prepare('DELETE FROM recovery_codes WHERE number_mac = ?').run(key);
      return matches;
    })();
  }

  /** Rebinds an account to a new identity. Everything else about it stays. */
  replaceIdentity(
    aci: string,
    identityKey: Uint8Array,
    registrationId: number,
    signedPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array },
    kyberPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array },
    oneTimePreKeys: { keyId: number; publicKey: Uint8Array }[],
  ): void {
    this.db.transaction(() => {
      this.db
        .prepare('UPDATE accounts SET identity_key = ?, registration_id = ? WHERE aci = ?')
        .run(Buffer.from(identityKey), registrationId, aci);
      // Everything published under the old identity is now unusable, and
      // leaving it would hand callers prekeys signed by a key nobody holds.
      this.db.prepare('DELETE FROM one_time_prekeys WHERE aci = ?').run(aci);
      this.writeSignedPreKey(aci, signedPreKey);
      this.writeKyberPreKey(aci, kyberPreKey);
      this.addOneTimePreKeys(aci, oneTimePreKeys);
    })();
  }

  sweepRecoveryCodes(now = Date.now()): number {
    return this.db.prepare('DELETE FROM recovery_codes WHERE expires_at < ?').run(now).changes;
  }

  sweepChallenges(): number {
    return this.db.prepare('DELETE FROM auth_challenges WHERE expires_at < ?').run(Date.now()).changes;
  }

  /** Used by the audit script to show exactly what the relay is holding. */
  tableNames(): string[] {
    const rows = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as { name: string }[];
    return rows.map((r) => r.name);
  }

  dumpTable(name: string): Record<string, unknown>[] {
    if (!this.tableNames().includes(name)) throw new Error(`unknown table ${name}`);
    return this.db.prepare(`SELECT * FROM "${name}"`).all() as Record<string, unknown>[];
  }
}
