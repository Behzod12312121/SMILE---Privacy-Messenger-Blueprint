import {
  PrivateKey,
  PublicKey,
  SenderCertificate,
  ServerCertificate,
} from '@signalapp/libsignal-client';
import { randomBytes } from 'node:crypto';
import { OBLIVIOUS_INFO, SENDER_CERT_TTL_MS, bytes, type Bytes } from '@millygram/protocol';
import type { Store } from './db.js';

const STATE_TRUST_ROOT = 'trust_root_private';
const STATE_SIGNING_KEY = 'sender_cert_signing_private';
const STATE_OBLIVIOUS_KEY = 'oblivious_gateway_private';
const STATE_AUTH_KEY = 'auth_token_hmac';
const SERVER_CERT_KEY_ID = 1;

/**
 * The only long-lived secrets the server holds. None of them can decrypt a
 * message: the trust root and signing key exist purely to certify "this ACI
 * really is bound to this identity key", and the auth key only mints bearer
 * tokens for the account's own mailbox.
 */
export class ServerIdentity {
  private constructor(
    private readonly trustRootPrivate: PrivateKey,
    private readonly signingPrivate: PrivateKey,
    private readonly obliviousPrivate: PrivateKey,
    private readonly serverCertificate: ServerCertificate,
    readonly authKey: Buffer,
  ) {}

  static load(store: Store): ServerIdentity {
    const trustRootPrivate = loadOrCreateKey(store, STATE_TRUST_ROOT);
    const signingPrivate = loadOrCreateKey(store, STATE_SIGNING_KEY);
    const obliviousPrivate = loadOrCreateKey(store, STATE_OBLIVIOUS_KEY);

    let authKey = store.getState(STATE_AUTH_KEY);
    if (!authKey) {
      authKey = randomBytes(32);
      store.putState(STATE_AUTH_KEY, authKey);
    }

    const serverCertificate = ServerCertificate.new(
      SERVER_CERT_KEY_ID,
      signingPrivate.getPublicKey(),
      trustRootPrivate,
    );

    return new ServerIdentity(trustRootPrivate, signingPrivate, obliviousPrivate, serverCertificate, authKey);
  }

  get trustRootPublic(): PublicKey {
    return this.trustRootPrivate.getPublicKey();
  }

  /** Published so clients can seal submissions the oblivious relay cannot read. */
  get obliviousPublic(): PublicKey {
    return this.obliviousPrivate.getPublicKey();
  }

  /**
   * Compromising this key reveals only what the gateway already sees legitimately
   * — a bucket id, a proof of work, and a ciphertext it cannot decrypt. It never
   * exposes message content, and never a sender.
   */
  openOblivious(sealed: Uint8Array): Bytes | null {
    try {
      return bytes(this.obliviousPrivate.open(bytes(sealed), OBLIVIOUS_INFO));
    } catch {
      return null;
    }
  }

  /**
   * Lets a client send sealed-sender messages: the recipient can verify the
   * sender's identity against the trust root without the server ever seeing
   * who sent what.
   */
  issueSenderCertificate(aci: string, deviceId: number, identityKey: PublicKey, now = Date.now()): {
    certificate: SenderCertificate;
    expiresAt: number;
  } {
    const expiresAt = now + SENDER_CERT_TTL_MS;
    const certificate = SenderCertificate.new(
      aci,
      null,
      deviceId,
      identityKey,
      expiresAt,
      this.serverCertificate,
      this.signingPrivate,
    );
    return { certificate, expiresAt };
  }
}

function loadOrCreateKey(store: Store, stateKey: string): PrivateKey {
  const existing = store.getState(stateKey);
  if (existing) return PrivateKey.deserialize(bytes(existing));
  const generated = PrivateKey.generate();
  store.putState(stateKey, generated.serialize());
  return generated;
}

/**
 * A prekey bundle is only worth serving if it is self-consistent. Clients
 * verify this too, but rejecting it here stops a compromised or buggy client
 * from poisoning other people's sessions.
 */
export function verifyPreKeySignature(
  identityKey: PublicKey,
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return identityKey.verify(bytes(publicKey), bytes(signature));
  } catch {
    return false;
  }
}

export function verifySignature(identityKey: PublicKey, payload: Uint8Array, signature: Uint8Array): boolean {
  return verifyPreKeySignature(identityKey, payload, signature);
}

export function parseIdentityKey(input: Uint8Array): PublicKey | null {
  try {
    return PublicKey.deserialize(bytes(input));
  } catch {
    return null;
  }
}
