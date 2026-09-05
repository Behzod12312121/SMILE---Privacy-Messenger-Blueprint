import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { AUTH_CHALLENGE_TTL_MS, authSigningPayload, b64, unb64 } from '@millygram/protocol';
import type { Store } from './db.js';
import { ServerIdentity, parseIdentityKey, verifySignature } from './identity.js';

export interface AuthenticatedCaller {
  aci: string;
  deviceId: number;
}

/** 16 bytes of UUID, one of device id, eight of expiry. */
const TOKEN_PAYLOAD_BYTES = 25;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function uuidToBytes(uuid: string): Buffer {
  if (!UUID_RE.test(uuid)) throw new Error('not a canonical uuid');
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bytesToUuid(bytes: Buffer): string {
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Authentication is possession of the account's identity private key, proved
 * against a single-use server nonce. There are no passwords, so there is no
 * password database to leak and nothing for the server to hold that would let
 * it impersonate a user.
 */
export class Authenticator {
  constructor(
    private readonly store: Store,
    private readonly identity: ServerIdentity,
    private readonly tokenTtlMs: number,
  ) {}

  /**
   * A challenge is always returned, so this endpoint cannot be used to learn
   * which account identifiers are real. It is only *stored* for accounts that
   * exist: storing one for every identifier anybody cares to invent turns an
   * unauthenticated endpoint into unbounded write access to the database.
   *
   * A challenge for an unknown account therefore simply fails to verify later,
   * which is the same outcome an attacker sees either way.
   */
  issueChallenge(aci: string): { nonce: string; expiresAt: number } {
    const nonce = randomBytes(32);
    const expiresAt = Date.now() + AUTH_CHALLENGE_TTL_MS;
    if (this.store.accountByAci(aci)) this.store.putChallenge(nonce, aci, expiresAt);
    return { nonce: b64(nonce), expiresAt };
  }

  verifyChallengeResponse(aci: string, deviceId: number, nonceB64: string, signatureB64: string): boolean {
    const account = this.store.accountByAci(aci);
    if (!account || account.device_id !== deviceId) return false;

    const nonce = unb64(nonceB64);
    if (!this.store.consumeChallenge(nonce, aci)) return false;

    const identityKey = parseIdentityKey(account.identity_key);
    if (!identityKey) return false;

    return verifySignature(identityKey, authSigningPayload(aci, deviceId, nonce), unb64(signatureB64));
  }

  /**
   * Fixed binary layout rather than a delimited string: 16 bytes of raw UUID,
   * one byte of device id, eight bytes of expiry. Delimited encodings invite
   * the question "what if a field contains the delimiter", and the answer is
   * only ever "it does not today". Fixed offsets cannot be mis-parsed at all.
   */
  mintToken(aci: string, deviceId: number, now = Date.now()): { token: string; expiresAt: number } {
    const expiresAt = now + this.tokenTtlMs;

    const payload = Buffer.alloc(TOKEN_PAYLOAD_BYTES);
    uuidToBytes(aci).copy(payload, 0);
    payload.writeUInt8(deviceId, 16);
    payload.writeBigUInt64BE(BigInt(expiresAt), 17);

    const mac = createHmac('sha256', this.identity.authKey).update(payload).digest();
    return { token: `${payload.toString('base64url')}.${mac.toString('base64url')}`, expiresAt };
  }

  verifyToken(token: string, now = Date.now()): AuthenticatedCaller | null {
    const dot = token.indexOf('.');
    if (dot <= 0) return null;

    const payloadB64 = token.slice(0, dot);
    const macB64 = token.slice(dot + 1);

    let payload: Buffer;
    let mac: Buffer;
    try {
      payload = Buffer.from(payloadB64, 'base64url');
      mac = Buffer.from(macB64, 'base64url');
    } catch {
      return null;
    }

    if (payload.length !== TOKEN_PAYLOAD_BYTES) return null;

    const expected = createHmac('sha256', this.identity.authKey).update(payload).digest();
    if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) return null;

    const aci = bytesToUuid(payload.subarray(0, 16));
    const deviceId = payload.readUInt8(16);
    const expiresAt = Number(payload.readBigUInt64BE(17));

    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) return null;

    // A signed token outlives the account it names unless this is checked, so a
    // deleted or re-registered account would keep answering for its old holder
    // until the token expired.
    const account = this.store.accountByAci(aci);
    if (!account || account.device_id !== deviceId) return null;

    return { aci, deviceId };
  }
}
