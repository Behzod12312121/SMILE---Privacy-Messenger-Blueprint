import {
  IdentityKeyPair,
  KEMKeyPair,
  KyberPreKeyRecord,
  PreKeyRecord,
  PrivateKey,
  SignedPreKeyRecord,
} from '@signalapp/libsignal-client';
import { randomInt } from 'node:crypto';
import { ONE_TIME_PREKEY_BATCH, b64, bytes } from '@millygram/protocol';
import type { ProtocolStores } from './store.js';

export interface PublicPreKeyMaterial {
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  kyberPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: { keyId: number; publicKey: string }[];
}

/** libsignal registration ids are 14 bits, and zero is reserved. */
export function generateRegistrationId(): number {
  return randomInt(1, 0x3fff);
}

export async function generateSignedPreKey(
  identity: IdentityKeyPair,
  keyId: number,
  stores: ProtocolStores,
): Promise<{ keyId: number; publicKey: string; signature: string }> {
  const pair = PrivateKey.generate();
  const publicKey = pair.getPublicKey();
  const signature = identity.privateKey.sign(publicKey.serialize());
  const record = SignedPreKeyRecord.new(keyId, Date.now(), publicKey, pair, signature);
  await stores.signedPreKey.saveSignedPreKey(keyId, record);
  return { keyId, publicKey: b64(publicKey.serialize()), signature: b64(signature) };
}

/**
 * The Kyber prekey is what makes the initial agreement post-quantum: X25519 and
 * ML-KEM outputs are both mixed into the root key, so an adversary archiving
 * traffic today must break both to read it later.
 */
export async function generateKyberPreKey(
  identity: IdentityKeyPair,
  keyId: number,
  stores: ProtocolStores,
): Promise<{ keyId: number; publicKey: string; signature: string }> {
  const pair = KEMKeyPair.generate();
  const publicKey = pair.getPublicKey();
  const signature = identity.privateKey.sign(publicKey.serialize());
  const record = KyberPreKeyRecord.new(keyId, Date.now(), pair, signature);
  await stores.kyberPreKey.saveKyberPreKey(keyId, record);
  return { keyId, publicKey: b64(publicKey.serialize()), signature: b64(signature) };
}

export async function generateOneTimePreKeys(
  firstId: number,
  count: number,
  stores: ProtocolStores,
): Promise<{ keyId: number; publicKey: string }[]> {
  const published: { keyId: number; publicKey: string }[] = [];
  for (let offset = 0; offset < count; offset += 1) {
    const keyId = firstId + offset;
    const pair = PrivateKey.generate();
    const publicKey = pair.getPublicKey();
    await stores.preKey.savePreKey(keyId, PreKeyRecord.new(keyId, publicKey, pair));
    published.push({ keyId, publicKey: b64(publicKey.serialize()) });
  }
  return published;
}

export async function generateInitialKeys(
  identity: IdentityKeyPair,
  stores: ProtocolStores,
): Promise<PublicPreKeyMaterial> {
  return {
    signedPreKey: await generateSignedPreKey(identity, 1, stores),
    kyberPreKey: await generateKyberPreKey(identity, 1, stores),
    oneTimePreKeys: await generateOneTimePreKeys(1, ONE_TIME_PREKEY_BATCH, stores),
  };
}

export function deserializeIdentity(raw: Uint8Array): IdentityKeyPair {
  return IdentityKeyPair.deserialize(bytes(raw));
}
