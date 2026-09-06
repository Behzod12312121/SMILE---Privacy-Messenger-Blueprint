import {
  ErrorCode,
  Fingerprint,
  IdentityKeyPair,
  KEMPublicKey,
  LibSignalErrorBase,
  PreKeyBundle,
  ProtocolAddress,
  PublicKey,
  SenderCertificate,
  processPreKeyBundle,
  sealedSenderDecryptMessage,
  sealedSenderEncryptMessage,
} from '@signalapp/libsignal-client';
import { z } from 'zod';
import {
  DEVICE_ID_PRIMARY,
  MAX_PLAINTEXT_BYTES,
  ONE_TIME_PREKEY_BATCH,
  REGISTRATION_POW_DIFFICULTY,
  solveRegistrationWork,
  ONE_TIME_PREKEY_LOW_WATER,
  b64,
  bytes,
  isValidUsername,
  pad,
  registrationSigningPayload,
  unb64,
  unpad,
  type PreKeyBundleResponse,
  type RegisterRequest,
  type StoredEnvelope,
} from '@millygram/protocol';
import { buildStores, LocalStore, type ProtocolStores } from './store.js';
import { deserializeIdentity, generateInitialKeys, generateOneTimePreKeys, generateRegistrationId } from './keys.js';
import { Transport, TransportError } from './transport.js';

export { LocalStore, MillygramIdentityStore, buildStores } from './store.js';
export type { ProtocolStores } from './store.js';
export { Transport, TransportError } from './transport.js';
export { generateInitialKeys, generateRegistrationId } from './keys.js';

const META_IDENTITY = 'identity';
const META_REGISTRATION_ID = 'registrationId';
const META_ACI = 'aci';
const META_USERNAME = 'username';
const META_DEVICE_ID = 'deviceId';
const META_BUCKET_ID = 'bucketId';
const META_POW_DIFFICULTY = 'powDifficulty';
const META_TRUST_ROOT = 'trustRoot';
const META_SENDER_CERT = 'senderCert';
const META_SENDER_CERT_EXPIRY = 'senderCertExpiresAt';
const META_NEXT_PREKEY_ID = 'nextPreKeyId';
const META_CURSOR = 'bucketCursor';
const peerBucketMeta = (aci: string): string => `peerBucket:${aci}`;

/**
 * What travels inside the ciphertext. Text only: no attachment field, no MIME
 * type, no URL to fetch, so the whole class of media-parser attacks has nowhere
 * to enter. The payload is padded to a constant size before encryption, so its
 * length says nothing either.
 */
const MessagePayload = z.object({
  v: z.literal(1),
  body: z.string().min(1).max(MAX_PLAINTEXT_BYTES),
  sentAt: z.number().int().positive(),
  /**
   * The sender's own delivery bucket, so the recipient can reply without asking
   * the relay anything. It rides inside the ciphertext precisely so that
   * knowing where to answer never becomes a query the relay can observe.
   */
  bucketId: z.number().int().min(0),
});
export type MessagePayload = z.infer<typeof MessagePayload>;

export interface IncomingMessage {
  senderAci: string;
  senderDeviceId: number;
  body: string;
  sentAt: number;
  receivedAt: number;
}

export interface ClientOptions {
  serverUrl: string;
  databasePath: string;
  passphrase: string;
  /**
   * Send messages through an oblivious relay run by a different operator, so
   * the gateway never sees the sender's address. Omit it and submissions go
   * straight to the gateway, which is still anonymous in every other respect.
   */
  obliviousRelayUrl?: string;
}

export interface RegisterOptions extends ClientOptions {
  username: string;
}

const SAFETY_NUMBER_ITERATIONS = 5200;
const SAFETY_NUMBER_VERSION = 2;

export class MillygramClient {
  /** Serialises envelope handling so the cursor can never move backwards. */
  private queue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly store: LocalStore,
    private readonly stores: ProtocolStores,
    private readonly transport: Transport,
    private readonly identity: IdentityKeyPair,
    readonly aci: string,
    readonly username: string,
    readonly deviceId: number,
    readonly bucketId: number,
    private readonly powDifficulty: number,
    private readonly trustRoot: PublicKey,
  ) {}

  static async register(options: RegisterOptions): Promise<MillygramClient> {
    if (!isValidUsername(options.username)) {
      throw new Error('username must be 3-32 characters of a-z, 0-9 or underscore');
    }

    const store = LocalStore.open(options.databasePath, options.passphrase);
    if (store.getMeta(META_ACI)) {
      store.close();
      throw new Error('this database already holds an account; open it instead of registering');
    }

    const identity = IdentityKeyPair.generate();
    const registrationId = generateRegistrationId();

    store.setMeta(META_IDENTITY, identity.serialize());
    store.setMetaNumber(META_REGISTRATION_ID, registrationId);
    store.setMetaNumber(META_DEVICE_ID, DEVICE_ID_PRIMARY);
    store.setMetaString(META_USERNAME, options.username);

    const stores = buildStores(store, identity, registrationId);
    const material = await generateInitialKeys(identity, stores);
    store.setMetaNumber(META_NEXT_PREKEY_ID, ONE_TIME_PREKEY_BATCH + 1);

    const unsigned: Omit<RegisterRequest, 'signature' | 'workNonce'> = {
      username: options.username,
      deviceId: DEVICE_ID_PRIMARY,
      registrationId,
      identityKey: b64(identity.publicKey.serialize()),
      signedPreKey: material.signedPreKey,
      kyberPreKey: material.kyberPreKey,
      oneTimePreKeys: material.oneTimePreKeys,
      timestamp: Date.now(),
    };
    const payload = registrationSigningPayload(unsigned);
    const signature = identity.privateKey.sign(payload);

    const transport = new Transport(options.serverUrl, null, options.obliviousRelayUrl ?? null);
    // Registration is charged in CPU rather than to an address. Every user on
    // an Uzbek mobile network shares a handful of public addresses, so an
    // address-based limit would ration signups for a whole carrier; work costs
    // the same wherever it is solved. The retry exists so the gateway can raise
    // the price during a flood without every installed client breaking.
    let registered;
    try {
      let difficulty = REGISTRATION_POW_DIFFICULTY;
      for (let attempt = 0; ; attempt += 1) {
        const workNonce = solveRegistrationWork(payload, difficulty);
        try {
          registered = await transport.register({
            ...unsigned,
            signature: b64(signature),
            workNonce,
          });
          break;
        } catch (error) {
          const harder =
            error instanceof TransportError &&
            error.code === 'work_required' &&
            error.requiredDifficulty !== undefined &&
            error.requiredDifficulty > difficulty;
          if (!harder || attempt > 0) throw error;
          difficulty = (error as TransportError).requiredDifficulty!;
        }
      }
    } catch (error) {
      store.close();
      throw error;
    }

    store.setMetaString(META_ACI, registered.aci);
    store.setMetaString(META_TRUST_ROOT, registered.trustRoot);
    store.setMetaNumber(META_BUCKET_ID, registered.bucketId);
    store.setMetaNumber(META_POW_DIFFICULTY, registered.powDifficulty);

    transport.setCredentials({
      aci: registered.aci,
      deviceId: DEVICE_ID_PRIMARY,
      sign: (payload) => bytes(identity.privateKey.sign(payload)),
    });

    return new MillygramClient(
      store,
      stores,
      transport,
      identity,
      registered.aci,
      options.username,
      DEVICE_ID_PRIMARY,
      registered.bucketId,
      registered.powDifficulty,
      PublicKey.deserialize(unb64(registered.trustRoot)),
    );
  }

  static async open(options: ClientOptions): Promise<MillygramClient> {
    const store = LocalStore.open(options.databasePath, options.passphrase);

    const identityRaw = store.getMeta(META_IDENTITY);
    const aci = store.getMetaString(META_ACI);
    const username = store.getMetaString(META_USERNAME);
    const registrationId = store.getMetaNumber(META_REGISTRATION_ID);
    const deviceId = store.getMetaNumber(META_DEVICE_ID);
    const bucketId = store.getMetaNumber(META_BUCKET_ID);
    const powDifficulty = store.getMetaNumber(META_POW_DIFFICULTY);
    const trustRoot = store.getMetaString(META_TRUST_ROOT);

    if (
      !identityRaw ||
      !aci ||
      !username ||
      !trustRoot ||
      registrationId === null ||
      deviceId === null ||
      bucketId === null ||
      powDifficulty === null
    ) {
      store.close();
      throw new Error('this database does not hold a complete account');
    }

    const identity = deserializeIdentity(identityRaw);
    const stores = buildStores(store, identity, registrationId);
    const transport = new Transport(
      options.serverUrl,
      { aci, deviceId, sign: (payload) => bytes(identity.privateKey.sign(payload)) },
      options.obliviousRelayUrl ?? null,
    );

    return new MillygramClient(
      store,
      stores,
      transport,
      identity,
      aci,
      username,
      deviceId,
      bucketId,
      powDifficulty,
      PublicKey.deserialize(unb64(trustRoot)),
    );
  }

  private get localAddress(): ProtocolAddress {
    return ProtocolAddress.new(this.aci, this.deviceId);
  }

  /**
   * Establishes a session from a published prekey bundle. The signatures are
   * checked here as well as at the relay: a client that relies on the server's
   * verification has no protection against the server.
   */
  private async ensureSession(aci: string, deviceId: number): Promise<ProtocolAddress> {
    const address = ProtocolAddress.new(aci, deviceId);
    if (await this.stores.session.getSession(address)) return address;

    const bundle = await this.transport.fetchPreKeyBundle(aci);
    const identityKey = PublicKey.deserialize(unb64(bundle.identityKey));

    if (!identityKey.verify(unb64(bundle.signedPreKey.publicKey), unb64(bundle.signedPreKey.signature))) {
      throw new Error(`signed prekey for ${aci} is not signed by the advertised identity key`);
    }
    if (!identityKey.verify(unb64(bundle.kyberPreKey.publicKey), unb64(bundle.kyberPreKey.signature))) {
      throw new Error(`kyber prekey for ${aci} is not signed by the advertised identity key`);
    }

    this.store.setMetaNumber(peerBucketMeta(aci), bundle.bucketId);

    await processPreKeyBundle(
      toPreKeyBundle(bundle, identityKey),
      address,
      this.localAddress,
      this.stores.session,
      this.stores.identity,
    );
    return address;
  }

  private async deliveryCertificate(): Promise<SenderCertificate> {
    const cached = this.store.getMeta(META_SENDER_CERT);
    const expiresAt = this.store.getMetaNumber(META_SENDER_CERT_EXPIRY);
    if (cached && expiresAt !== null && expiresAt - 60_000 > Date.now()) {
      return SenderCertificate.deserialize(cached);
    }

    const fetched = await this.transport.fetchDeliveryCertificate();
    const certificate = SenderCertificate.deserialize(unb64(fetched.certificate));

    if (!certificate.validate(this.trustRoot, Date.now())) {
      throw new Error('the relay issued a delivery certificate that does not chain to the pinned trust root');
    }

    this.store.setMeta(META_SENDER_CERT, certificate.serialize());
    this.store.setMetaNumber(META_SENDER_CERT_EXPIRY, fetched.expiresAt);
    return certificate;
  }

  async resolveUsername(username: string): Promise<{ aci: string; deviceId: number; bucketId: number }> {
    const found = await this.transport.lookupUsername(username);
    this.store.setMetaNumber(peerBucketMeta(found.aci), found.bucketId);
    return found;
  }

  async send(recipient: string, body: string): Promise<void> {
    if (body.length === 0) throw new Error('message body is empty');
    if (Buffer.byteLength(body, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw new Error(`message body exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
    }

    const target = isValidUsername(recipient)
      ? await this.resolveUsername(recipient)
      : { aci: recipient, deviceId: DEVICE_ID_PRIMARY };

    // Everything from here on reads and writes the session record, and the
    // Double Ratchet is read-modify-write: two sends that interleave both
    // encrypt from the same state and the second write discards the first's
    // ratchet advance. The sender sees two successes, the relay accepts two
    // envelopes, and the recipient can only follow one chain — so one message
    // is silently undeliverable. Sharing the queue that serialises envelope
    // handling keeps every mutation of that record in one order, which also
    // covers a send racing an incoming message.
    return this.exclusive(async () => {
      const address = await this.ensureSession(target.aci, target.deviceId);
      const bucketId = this.store.getMetaNumber(peerBucketMeta(target.aci));
      if (bucketId === null) throw new Error(`no delivery bucket known for ${target.aci}`);

      const payload: MessagePayload = { v: 1, body, sentAt: Date.now(), bucketId: this.bucketId };

      const sealed = await sealedSenderEncryptMessage(
        bytes(Buffer.from(JSON.stringify(payload), 'utf8')),
        address,
        await this.deliveryCertificate(),
        this.stores.session,
        this.stores.identity,
      );

      // Padded after encryption, not before: the ciphertext itself grows and
      // shrinks with ratchet state, so only padding the finished envelope makes
      // every envelope the same size.
      await this.transport.submit(bucketId, pad(sealed), this.powDifficulty);
    });
  }

  /**
   * Runs a task after everything already queued, and keeps the chain alive
   * when the task rejects so one failed send cannot wedge every later one.
   */
  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const result = this.queue.then(task);
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /**
   * Bucket members receive every envelope sent to the bucket. Anything not
   * addressed to us fails to open and is dropped without a word — that silence
   * is what keeps the relay from learning who a message was for.
   */
  async openEnvelope(envelope: StoredEnvelope): Promise<IncomingMessage | null> {
    try {
      const result = await sealedSenderDecryptMessage(
        unpad(unb64(envelope.content)),
        this.trustRoot,
        Date.now(),
        null,
        this.aci,
        this.deviceId,
        this.stores.session,
        this.stores.identity,
        this.stores.preKey,
        this.stores.signedPreKey,
        this.stores.kyberPreKey,
      );

      const parsed = MessagePayload.safeParse(JSON.parse(Buffer.from(result.message()).toString('utf8')));
      if (!parsed.success) return null;

      // Remember where to answer, learned from the message itself rather than
      // from the relay.
      //
      // First value wins, and a later message can never change it. The field is
      // attacker-controlled: a peer who could rewrite it at will could point
      // our replies at any bucket they liked, forcing every member of that
      // bucket to download traffic they never asked for. Pinning it on first
      // sight removes that lever.
      //
      // We deliberately do NOT verify it against the relay. Asking "which
      // bucket does this account use" would tell the relay that we are about to
      // talk to them, which is precisely the social-graph disclosure the whole
      // design exists to avoid. The residual — a peer misrouting replies
      // addressed to themselves — is bounded by the relay's per-bucket rate
      // limit and costs the liar their own messages.
      const senderAci = result.senderUuid();
      if (this.store.getMetaNumber(peerBucketMeta(senderAci)) === null) {
        this.store.setMetaNumber(peerBucketMeta(senderAci), parsed.data.bucketId);
      }

      return {
        senderAci,
        senderDeviceId: result.deviceId(),
        body: parsed.data.body,
        sentAt: parsed.data.sentAt,
        receivedAt: Date.now(),
      };
    } catch (error) {
      // Most failures here are simply other people's mail: a bucket member
      // receives every envelope sent to the bucket, and the ones not addressed
      // to us cannot open. Those are dropped in silence by design.
      //
      // An identity mismatch is different in kind. It means something claiming
      // to be a known contact arrived under a different identity key, which is
      // what a relay substituting keys looks like from here. Swallowing it
      // alongside ordinary bucket noise would hide the one event the safety
      // number exists to catch.
      if (isUntrustedIdentity(error)) this.onUntrustedIdentity?.(envelope);
      return null;
    }
  }

  /**
   * Forgets everything pinned about a contact: the session and the identity key.
   *
   * This is the only way out of an identity change. Until it is called the old
   * key stays pinned, so every message the contact sends is rejected and the
   * conversation is dead in both directions — which is correct when someone is
   * substituting keys, and wrong when the contact simply reinstalled, the far
   * commoner case. The next message re-establishes from a fresh bundle and
   * pins whatever it carries, so this puts the conversation back into
   * trust-on-first-use and must be an explicit choice by someone who has
   * looked at the safety number, never something the client decides.
   */
  forgetPeer(aci: string): void {
    const address = `${aci}.${DEVICE_ID_PRIMARY}`;
    this.store.deleteRecord('sessions', address);
    this.store.deleteIdentity(address);
  }

  /**
   * Called when an envelope fails to open because the sender's identity key is
   * not the one pinned for them. The UI should surface this rather than let it
   * pass as noise.
   */
  onUntrustedIdentity: ((envelope: StoredEnvelope) => void) | undefined;

  private get cursor(): number {
    return this.store.getMetaNumber(META_CURSOR) ?? 0;
  }

  private enqueue(
    envelopes: StoredEnvelope[],
    onMessage: (message: IncomingMessage) => void | Promise<void>,
  ): Promise<void> {
    this.queue = this.queue.then(async () => {
      for (const envelope of envelopes) {
        if (envelope.seq <= this.cursor) continue;
        const message = await this.openEnvelope(envelope);
        this.store.setMetaNumber(META_CURSOR, envelope.seq);
        if (message) await onMessage(message);
      }
    });
    return this.queue;
  }

  async connect(onMessage: (message: IncomingMessage) => void | Promise<void>): Promise<void> {
    await this.transport.connect({
      onEnvelope: (envelope) => {
        void this.enqueue([envelope], onMessage);
      },
      onCaughtUp: () => {
        void this.replenishPreKeys();
      },
    });
    await this.catchUp(onMessage);
  }

  /** Collects anything that arrived in the bucket while this client was away. */
  async catchUp(onMessage: (message: IncomingMessage) => void | Promise<void>): Promise<void> {
    await this.enqueue(await this.transport.since(this.cursor), onMessage);
  }

  /**
   * One-time prekeys are consumed by each new session that starts with us. If
   * they run out, new contacts fall back to a bundle without one, which is
   * weaker, so the pool is topped up as it drains.
   */
  async replenishPreKeys(): Promise<void> {
    try {
      const remaining = await this.transport.remainingOneTimePreKeys();
      if (remaining > ONE_TIME_PREKEY_LOW_WATER) return;

      const firstId = this.store.getMetaNumber(META_NEXT_PREKEY_ID) ?? ONE_TIME_PREKEY_BATCH + 1;
      const count = ONE_TIME_PREKEY_BATCH - remaining;
      const generated = await generateOneTimePreKeys(firstId, count, this.stores);

      await this.transport.replenishKeys({ oneTimePreKeys: generated });
      this.store.setMetaNumber(META_NEXT_PREKEY_ID, firstId + count);
    } catch (error) {
      if (error instanceof TransportError) return;
      throw error;
    }
  }

  /**
   * The number both people compare out of band. It is derived only from the two
   * identity keys, so a relay that swapped either one cannot make the two sides
   * agree.
   */
  async safetyNumber(peerAci: string): Promise<string> {
    const peer = await this.stores.identity.getIdentity(ProtocolAddress.new(peerAci, DEVICE_ID_PRIMARY));
    if (!peer) throw new Error(`no identity key stored for ${peerAci}; exchange a message first`);

    return Fingerprint.new(
      SAFETY_NUMBER_ITERATIONS,
      SAFETY_NUMBER_VERSION,
      bytes(Buffer.from(this.aci, 'utf8')),
      this.identity.publicKey,
      bytes(Buffer.from(peerAci, 'utf8')),
      peer,
    )
      .displayableFingerprint()
      .toString();
  }

  close(): void {
    this.transport.disconnect();
    this.store.close();
  }
}

function toPreKeyBundle(bundle: PreKeyBundleResponse, identityKey: PublicKey): PreKeyBundle {
  return PreKeyBundle.new(
    bundle.registrationId,
    bundle.deviceId,
    bundle.oneTimePreKey ? bundle.oneTimePreKey.keyId : null,
    bundle.oneTimePreKey ? PublicKey.deserialize(unb64(bundle.oneTimePreKey.publicKey)) : null,
    bundle.signedPreKey.keyId,
    PublicKey.deserialize(unb64(bundle.signedPreKey.publicKey)),
    unb64(bundle.signedPreKey.signature),
    identityKey,
    bundle.kyberPreKey.keyId,
    KEMPublicKey.deserialize(unb64(bundle.kyberPreKey.publicKey)),
    unb64(bundle.kyberPreKey.signature),
  );
}

/**
 * libsignal reports an identity mismatch with a typed error code rather than a
 * message string, so this check does not depend on wording that could change.
 */
function isUntrustedIdentity(error: unknown): boolean {
  return LibSignalErrorBase.is(error, ErrorCode.UntrustedIdentity);
}
