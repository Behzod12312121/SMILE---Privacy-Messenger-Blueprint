import Database from 'better-sqlite3';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import {
  Direction,
  IdentityChange,
  IdentityKeyPair,
  IdentityKeyStore,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyRecord,
  PreKeyStore,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
} from '@signalapp/libsignal-client';
import { bytes, type Bytes } from '@millygram/protocol';

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS vault (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  kdf_salt      BLOB NOT NULL,
  wrapped_key   BLOB NOT NULL,
  kdf_n         INTEGER NOT NULL,
  kdf_r         INTEGER NOT NULL,
  kdf_p         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta          (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions      (address TEXT PRIMARY KEY, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS identities    (address TEXT PRIMARY KEY, key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS prekeys       (id INTEGER PRIMARY KEY, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS signed_prekeys(id INTEGER PRIMARY KEY, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS kyber_prekeys (id INTEGER PRIMARY KEY, record BLOB NOT NULL, used INTEGER NOT NULL DEFAULT 0);
`;

/**
 * scrypt is memory-hard and ships with Node, so there is no native build step
 * on the path to a protected database. Argon2id would be the better choice and
 * is the intended upgrade; the parameters live in the vault row so an existing
 * database can be rewrapped without losing anything.
 */
const KDF_N = 65536;
const KDF_R = 8;
const KDF_P = 1;
const KDF_MAXMEM = 128 * KDF_N * KDF_R * 2;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function deriveKey(passphrase: string, salt: Buffer, n: number, r: number, p: number): Buffer {
  return scryptSync(passphrase.normalize('NFKC'), salt, KEY_BYTES, {
    N: n,
    r,
    p,
    maxmem: 128 * n * r * 2,
  });
}

/**
 * Every stored value is bound to the exact row it belongs in. Without that
 * binding an attacker with write access to the file could move a valid
 * ciphertext from one key to another — swapping a contact's identity key for a
 * different one, for instance — without ever breaking the cipher.
 */
function aad(table: string, key: string): Buffer {
  return Buffer.from(`millygram/v1/${table}/${key}`, 'utf8');
}

/**
 * AES-256-GCM under `dek`, committing to `associated`.
 *
 * Layout is nonce ‖ ciphertext ‖ tag, with the tag last. That is where the
 * Java cipher puts it, and the Android client is where the vaults that matter
 * live; this side used to put the tag second and neither implementation could
 * open the other's storage. Nothing forced them to agree, because a vault is
 * per-device and never shared — which is why it went unnoticed until a
 * conformance vector asked. A backup, an export, or a second client would have
 * found it the hard way.
 */
function seal(dek: Buffer, associated: Buffer, plaintext: Uint8Array): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', dek, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(associated);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

function open(dek: Buffer, associated: Buffer, blob: Buffer): Bytes {
  if (blob.length < NONCE_BYTES + TAG_BYTES) throw new Error('stored value is truncated');
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const body = blob.subarray(NONCE_BYTES, blob.length - TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', dek, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(associated);
  decipher.setAuthTag(tag);
  return bytes(Buffer.concat([decipher.update(body), decipher.final()]));
}

/** The only tables readRecord/writeRecord/deleteRecord may name. */
const RECORD_TABLES = new Set(['sessions', 'prekeys', 'signed_prekeys', 'kyber_prekeys']);

const addressKey = (address: ProtocolAddress): string => `${address.name()}.${address.deviceId()}`;

export class LocalStore {
  private constructor(
    private readonly db: Database.Database,
    private readonly dek: Buffer,
  ) {}

  /**
   * Opens an existing vault or creates one. The data-encryption key is random
   * and never derived from the passphrase directly, so changing the passphrase
   * later rewraps one key instead of re-encrypting the whole database.
   */
  static open(path: string, passphrase: string): LocalStore {
    const db = new Database(path);
    db.exec(SCHEMA);

    const row = db.prepare('SELECT * FROM vault WHERE id = 1').get() as
      | { kdf_salt: Buffer; wrapped_key: Buffer; kdf_n: number; kdf_r: number; kdf_p: number }
      | undefined;

    if (!row) {
      const salt = randomBytes(16);
      const kek = deriveKey(passphrase, salt, KDF_N, KDF_R, KDF_P);
      const dek = randomBytes(KEY_BYTES);
      const wrapped = seal(kek, aad('vault', 'dek'), dek);
      // The passphrase-derived key has done its one job. Leaving it in memory
      // for the life of the process gives anyone who can read that memory a
      // second route to the vault.
      kek.fill(0);
      db.prepare(
        'INSERT INTO vault (id, kdf_salt, wrapped_key, kdf_n, kdf_r, kdf_p) VALUES (1, ?, ?, ?, ?, ?)',
      ).run(salt, wrapped, KDF_N, KDF_R, KDF_P);
      return new LocalStore(db, dek);
    }

    const kek = deriveKey(passphrase, row.kdf_salt, row.kdf_n, row.kdf_r, row.kdf_p);
    let dek: Buffer;
    try {
      dek = Buffer.from(open(kek, aad('vault', 'dek'), row.wrapped_key));
    } catch {
      db.close();
      throw new Error('wrong passphrase, or the local database has been tampered with');
    } finally {
      // Zeroed on every path, including the failure one — a wrong passphrase
      // still derived a key, and that key still sat in memory.
      kek.fill(0);
    }
    return new LocalStore(db, dek);
  }

  close(): void {
    this.dek.fill(0);
    this.db.close();
  }

  getMeta(key: string): Bytes | null {
    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get(key) as { value: Buffer } | undefined;
    return row ? open(this.dek, aad('meta', key), row.value) : null;
  }

  setMeta(key: string, value: Uint8Array): void {
    this.db
      .prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, seal(this.dek, aad('meta', key), value));
  }

  getMetaString(key: string): string | null {
    const value = this.getMeta(key);
    return value ? Buffer.from(value).toString('utf8') : null;
  }

  setMetaString(key: string, value: string): void {
    this.setMeta(key, Buffer.from(value, 'utf8'));
  }

  getMetaNumber(key: string): number | null {
    const value = this.getMetaString(key);
    return value === null ? null : Number.parseInt(value, 10);
  }

  setMetaNumber(key: string, value: number): void {
    this.setMetaString(key, String(value));
  }

  /**
   * Table names cannot be bound as SQL parameters, so they are interpolated —
   * and interpolation is only safe while the inputs are provably constant.
   * Checking against the schema means a future caller that arrives here with a
   * computed name fails loudly instead of building a query out of it. The
   * Android port carries the same guard.
   */
  private static requireKnownTable(table: string): void {
    if (!RECORD_TABLES.has(table)) throw new Error(`unknown table: ${table}`);
  }

  readRecord(table: string, id: string | number): Bytes | null {
    LocalStore.requireKnownTable(table);
    const column = typeof id === 'number' ? 'id' : 'address';
    const row = this.db.prepare(`SELECT record FROM "${table}" WHERE ${column} = ?`).get(id) as
      | { record: Buffer }
      | undefined;
    return row ? open(this.dek, aad(table, String(id)), row.record) : null;
  }

  writeRecord(table: string, id: string | number, record: Uint8Array): void {
    LocalStore.requireKnownTable(table);
    const column = typeof id === 'number' ? 'id' : 'address';
    this.db
      .prepare(
        `INSERT INTO "${table}" (${column}, record) VALUES (?, ?)
         ON CONFLICT(${column}) DO UPDATE SET record = excluded.record`,
      )
      .run(id, seal(this.dek, aad(table, String(id)), record));
  }

  deleteRecord(table: string, id: string | number): void {
    LocalStore.requireKnownTable(table);
    const column = typeof id === 'number' ? 'id' : 'address';
    this.db.prepare(`DELETE FROM "${table}" WHERE ${column} = ?`).run(id);
  }

  readIdentity(address: string): Bytes | null {
    const row = this.db.prepare('SELECT key FROM identities WHERE address = ?').get(address) as
      | { key: Buffer }
      | undefined;
    return row ? open(this.dek, aad('identities', address), row.key) : null;
  }

  writeIdentity(address: string, key: Uint8Array): void {
    this.db
      .prepare(
        'INSERT INTO identities (address, key) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET key = excluded.key',
      )
      .run(address, seal(this.dek, aad('identities', address), key));
  }

  /** Unpins a contact's identity. See MillygramClient.forgetPeer. */
  deleteIdentity(address: string): void {
    this.db.prepare('DELETE FROM identities WHERE address = ?').run(address);
  }

  markKyberUsed(id: number): void {
    this.db.prepare('UPDATE kyber_prekeys SET used = 1 WHERE id = ?').run(id);
  }
}

export class MillygramSessionStore extends SessionStore {
  constructor(private readonly store: LocalStore) {
    super();
  }

  override async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
    this.store.writeRecord('sessions', addressKey(name), record.serialize());
  }

  override async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    const raw = this.store.readRecord('sessions', addressKey(name));
    return raw ? SessionRecord.deserialize(raw) : null;
  }

  override async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
    const records: SessionRecord[] = [];
    for (const address of addresses) {
      const raw = this.store.readRecord('sessions', addressKey(address));
      if (!raw) throw new Error(`no session for ${addressKey(address)}`);
      records.push(SessionRecord.deserialize(raw));
    }
    return records;
  }
}

export class MillygramIdentityStore extends IdentityKeyStore {
  constructor(
    private readonly store: LocalStore,
    private readonly identity: IdentityKeyPair,
    private readonly registrationId: number,
  ) {
    super();
  }

  override async getIdentityKey(): Promise<PrivateKey> {
    return this.identity.privateKey;
  }

  override async getLocalRegistrationId(): Promise<number> {
    return this.registrationId;
  }

  override async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
    const address = addressKey(name);
    const existing = this.store.readIdentity(address);
    this.store.writeIdentity(address, key.serialize());

    if (!existing) return IdentityChange.NewOrUnchanged;
    const current = Buffer.from(existing);
    const incoming = Buffer.from(key.serialize());
    const same = current.length === incoming.length && timingSafeEqual(current, incoming);
    return same ? IdentityChange.NewOrUnchanged : IdentityChange.ReplacedExisting;
  }

  /**
   * Trust on first use, and refuse silently-changed keys thereafter. A changed
   * identity is exactly what a server-side impersonation attempt looks like, so
   * it must surface to the user as a safety-number warning rather than being
   * accepted automatically.
   */
  override async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, _direction: Direction): Promise<boolean> {
    const existing = this.store.readIdentity(addressKey(name));
    if (!existing) return true;
    const current = Buffer.from(existing);
    const incoming = Buffer.from(key.serialize());
    return current.length === incoming.length && timingSafeEqual(current, incoming);
  }

  override async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    const raw = this.store.readIdentity(addressKey(name));
    return raw ? PublicKey.deserialize(raw) : null;
  }
}

export class MillygramPreKeyStore extends PreKeyStore {
  constructor(private readonly store: LocalStore) {
    super();
  }

  override async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.store.writeRecord('prekeys', id, record.serialize());
  }

  override async getPreKey(id: number): Promise<PreKeyRecord> {
    const raw = this.store.readRecord('prekeys', id);
    if (!raw) throw new Error(`missing one-time prekey ${id}`);
    return PreKeyRecord.deserialize(raw);
  }

  override async removePreKey(id: number): Promise<void> {
    this.store.deleteRecord('prekeys', id);
  }
}

export class MillygramSignedPreKeyStore extends SignedPreKeyStore {
  constructor(private readonly store: LocalStore) {
    super();
  }

  override async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    this.store.writeRecord('signed_prekeys', id, record.serialize());
  }

  override async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    const raw = this.store.readRecord('signed_prekeys', id);
    if (!raw) throw new Error(`missing signed prekey ${id}`);
    return SignedPreKeyRecord.deserialize(raw);
  }
}

export class MillygramKyberPreKeyStore extends KyberPreKeyStore {
  constructor(private readonly store: LocalStore) {
    super();
  }

  override async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.store.writeRecord('kyber_prekeys', id, record.serialize());
  }

  override async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
    const raw = this.store.readRecord('kyber_prekeys', id);
    if (!raw) throw new Error(`missing kyber prekey ${id}`);
    return KyberPreKeyRecord.deserialize(raw);
  }

  override async markKyberPreKeyUsed(id: number): Promise<void> {
    this.store.markKyberUsed(id);
  }
}

export interface ProtocolStores {
  session: MillygramSessionStore;
  identity: MillygramIdentityStore;
  preKey: MillygramPreKeyStore;
  signedPreKey: MillygramSignedPreKeyStore;
  kyberPreKey: MillygramKyberPreKeyStore;
}

export function buildStores(
  store: LocalStore,
  identity: IdentityKeyPair,
  registrationId: number,
): ProtocolStores {
  return {
    session: new MillygramSessionStore(store),
    identity: new MillygramIdentityStore(store, identity, registrationId),
    preKey: new MillygramPreKeyStore(store),
    signedPreKey: new MillygramSignedPreKeyStore(store),
    kyberPreKey: new MillygramKyberPreKeyStore(store),
  };
}

export { KDF_MAXMEM };
