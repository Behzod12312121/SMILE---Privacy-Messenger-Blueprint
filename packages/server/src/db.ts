import Database from 'better-sqlite3';
import { createHash, randomUUID } from 'node:crypto';

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
  username        TEXT NOT NULL UNIQUE,
  device_id       INTEGER NOT NULL,
  bucket_id       INTEGER NOT NULL,
  registration_id INTEGER NOT NULL,
  identity_key    BLOB NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS accounts_bucket ON accounts (bucket_id);

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
  username: string;
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
  username: string;
  deviceId: number;
  registrationId: number;
  identityKey: Uint8Array;
  signedPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array };
  kyberPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKeys: { keyId: number; publicKey: Uint8Array }[];
}

export class Store {
  private readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.exec(SCHEMA);
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

  accountByUsername(username: string): AccountRow | null {
    return (this.db.prepare('SELECT * FROM accounts WHERE username = ?').get(username) as AccountRow) ?? null;
  }

  accountByAci(aci: string): AccountRow | null {
    return (this.db.prepare('SELECT * FROM accounts WHERE aci = ?').get(aci) as AccountRow) ?? null;
  }

  /**
   * Buckets fill in order so that every closed bucket holds exactly
   * `bucketSize` accounts. Only the newest bucket is ever partial, and it is
   * the only one where the anonymity set is smaller than advertised.
   */
  createAccount(account: NewAccount, bucketSize: number): { aci: string; bucketId: number } {
    const aci = randomUUID();
    const now = Date.now();

    return this.db.transaction(() => {
      const { total } = this.db.prepare('SELECT COUNT(*) AS total FROM accounts').get() as { total: number };
      const bucketId = Math.floor(total / bucketSize);

      this.db
        .prepare(
          `INSERT INTO accounts (aci, username, device_id, bucket_id, registration_id, identity_key, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          aci,
          account.username,
          account.deviceId,
          bucketId,
          account.registrationId,
          Buffer.from(account.identityKey),
          now,
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
   * Envelopes are removed on a timer, never on acknowledgement. An ack would
   * tell the relay which bucket member a given envelope belonged to.
   */
  sweepEnvelopes(olderThanMs: number): number {
    const cutoff = Date.now() - olderThanMs;
    // Digests are swept on the same cutoff. A replay of something older than
    // the envelope retention window has nothing left to duplicate.
    this.db.prepare('DELETE FROM submission_digests WHERE seen_at < ?').run(cutoff);
    return this.db.prepare('DELETE FROM envelopes WHERE arrived_at < ?').run(cutoff).changes;
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
