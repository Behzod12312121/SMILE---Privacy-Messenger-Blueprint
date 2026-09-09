import { randomBytes } from 'node:crypto';
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
  PADDED_PAYLOAD_BYTES,
  padPayload,
  Username,
  isValidUsername,
  usernameCandidates,
  usernameHash,
  usernameProof,
  ONE_TIME_PREKEY_BATCH,
  REGISTRATION_POW_DIFFICULTY,
  solveRegistrationWork,
  MAX_PREKEY_ID,
  ONE_TIME_PREKEY_LOW_WATER,
  PREKEY_ROTATION_MS,
  b64,
  bytes,
  isValidNickname,
  pad,
  registrationSigningPayload,
  unb64,
  unpad,
  type PreKeyBundleResponse,
  type RegisterRequest,
  type StoredEnvelope,
  GROUP_ID_BYTES,
  MAX_GROUP_MEMBERS,
  MAX_GROUP_REVISION,
  MAX_GROUPS,
  MAX_CURSOR_ADVANCE,
  GROUP_NAME_MAX,
  Aci,
  GroupId,
} from '@millygram/protocol';
import { buildStores, LocalStore, type ProtocolStores } from './store.js';
import {
  deserializeIdentity,
  generateInitialKeys,
  generateKyberPreKey,
  generateOneTimePreKeys,
  generateRegistrationId,
  generateSignedPreKey,
} from './keys.js';
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
const META_SIGNED_PREKEY_ID = 'signedPreKeyId';
const META_KYBER_PREKEY_ID = 'kyberPreKeyId';
const META_PREKEYS_ROTATED_AT = 'preKeysRotatedAt';
const META_CURSOR = 'bucketCursor';
const peerBucketMeta = (aci: string): string => `peerBucket:${aci}`;
const GROUP_INDEX = 'groups:index';
const groupMeta = (groupId: string): string => `group:${groupId}`;
const groupTombstone = (groupId: string): string => `groupGone:${groupId}`;

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
   * The sender's own handle, so a first message from a stranger can be shown
   * with a name on it rather than eight characters of an identifier.
   *
   * It rides inside the ciphertext for the same reason the bucket does: there
   * is deliberately no way to ask the relay who owns an account identifier,
   * because that question answered for anyone would enumerate every user. It is
   * a claim, not a proof — sealed sender establishes which account sent this,
   * not what it is called — so a recipient that cares checks it against the
   * directory, where the lookup runs the safe way round.
   */
  username: Username.optional(),
  /**
   * The sender's own delivery bucket, so the recipient can reply without asking
   * the relay anything. It rides inside the ciphertext precisely so that
   * knowing where to answer never becomes a query the relay can observe.
   */
  bucketId: z.number().int().min(0),
  /**
   * Which group this message belongs to, if any.
   *
   * Present only inside the ciphertext. The envelope carrying it is
   * indistinguishable from a one-to-one message: same size, same bucket, same
   * sealed sender. The gateway therefore cannot tell group traffic from
   * private traffic, let alone which group, which is the whole reason the
   * identifier lives here rather than in a field the server could index.
   */
  groupId: GroupId.optional(),
  /**
   * A group's membership and name, sent when it changes.
   *
   * Carried by whoever made the change and applied by everyone who receives
   * it. There is no server-side record to consult, so this is the only source
   * of truth — see the warning on applyGroupUpdate about what that means for
   * a dishonest member.
   */
  group: z
    .object({
      name: z.string().min(1).max(GROUP_NAME_MAX),
      members: z.array(Aci).min(1).max(MAX_GROUP_MEMBERS),
      /** Distinguishes a membership change from someone walking out. */
      event: z.enum(['update', 'leave']).default('update'),
      /** Orders concurrent edits; the highest revision seen wins. */
      revision: z.number().int().min(0).max(MAX_GROUP_REVISION),
    })
    .optional(),
});
export type MessagePayload = z.infer<typeof MessagePayload>;

/** A group as this device understands it. Held here and nowhere else. */
export interface GroupState {
  groupId: string;
  name: string;
  members: string[];
  revision: number;
}

export interface IncomingMessage {
  senderAci: string;
  senderDeviceId: number;
  body: string;
  /** What the sender says they are called. A claim; verify before trusting it. */
  senderUsername: string | null;
  sentAt: number;
  receivedAt: number;
  /** Set when this arrived in a group rather than a private thread. */
  groupId: string | null;
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
    // What a person registers is the nickname; the gateway appends the
    // discriminator and hands the whole handle back, because a discriminator the
    // user chose would be 0001 or their birth year, and the entropy it exists to
    // add would not be there.
    if (!isValidNickname(options.username)) {
      throw new Error('nickname must be 3-32 characters of a-z, 0-9 or underscore');
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

    const stores = buildStores(store, identity, registrationId);
    const material = await generateInitialKeys(identity, stores);
    store.setMetaNumber(META_NEXT_PREKEY_ID, ONE_TIME_PREKEY_BATCH + 1);
    store.setMetaNumber(META_SIGNED_PREKEY_ID, 1);
    store.setMetaNumber(META_KYBER_PREKEY_ID, 1);
    // These were generated a moment ago, so the rotation clock starts now
    // rather than at zero — otherwise every new account rotates on its first
    // connection, throwing away keys nobody has used yet.
    store.setMetaNumber(META_PREKEYS_ROTATED_AT, Date.now());

    // Handles the nickname could become, in the order libsignal offered them.
    // The gateway cannot pick one any more — picking would mean seeing the name
    // to hash it — so the client walks its own candidates and takes the next
    // when one is already claimed. Everything about a registration commits to
    // the hash, so a new candidate means a new signature and a new proof of
    // work; there is no way to retry a taken name cheaply, and no reason to
    // want one.
    const candidates = usernameCandidates(options.username);
    const transport = new Transport(options.serverUrl, null, options.obliviousRelayUrl ?? null);

    let registered: Awaited<ReturnType<Transport['register']>> | undefined;
    let username: string | undefined;
    try {
      for (const candidate of candidates) {
        const unsigned: Omit<RegisterRequest, 'signature' | 'workNonce'> = {
          usernameHash: b64(usernameHash(candidate)),
          usernameProof: b64(usernameProof(candidate)),
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

        // Registration is charged in CPU rather than to an address. Every user
        // on an Uzbek mobile network shares a handful of public addresses, so an
        // address-based limit would ration signups for a whole carrier; work
        // costs the same wherever it is solved. The retry exists so the gateway
        // can raise the price during a flood without every installed client
        // breaking.
        let difficulty = REGISTRATION_POW_DIFFICULTY;
        let taken = false;
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
            if (error instanceof TransportError && error.code === 'username_taken') {
              taken = true;
              break;
            }
            const harder =
              error instanceof TransportError &&
              error.code === 'work_required' &&
              error.requiredDifficulty !== undefined &&
              error.requiredDifficulty > difficulty;
            if (!harder || attempt > 0) throw error;
            difficulty = (error as TransportError).requiredDifficulty!;
          }
        }

        if (!taken) {
          username = candidate;
          break;
        }
      }

      if (!registered || !username) {
        throw new Error('every handle offered for that nickname is already taken');
      }
    } catch (error) {
      store.close();
      throw error;
    }

    // The handle this client chose and proved. The gateway holds only its hash
    // and could not return it, so this is the one copy that exists outside the
    // people who are told it.
    store.setMetaString(META_USERNAME, username);
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
      username,
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
    return this.sendPayload(recipient, body, undefined, undefined);
  }

  /**
   * The single path every outgoing message takes, private or group.
   *
   * A group message is an ordinary sealed-sender envelope with a group
   * identifier inside the ciphertext. Nothing about it looks different on the
   * wire — same size, same bucket, same padding — so the gateway cannot
   * separate group traffic from private traffic, or tell two groups apart.
   */
  private async sendPayload(
    recipient: string,
    body: string,
    groupId: string | undefined,
    control: MessagePayload['group'],
  ): Promise<void> {
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

      const payload: MessagePayload = {
        v: 1,
        body,
        sentAt: Date.now(),
        bucketId: this.bucketId,
        username: this.username,
        ...(groupId ? { groupId } : {}),
        ...(control ? { group: control } : {}),
      };

      // Padded to a constant size before sealing, so the ciphertext length --
      // which the envelope states in the clear, and every bucket member reads --
      // stops tracking what was written. Checked before the encrypt rather than
      // after it: pad() used to raise this after the ratchet had already
      // advanced, spending a message key on a send that then failed.
      const json = JSON.stringify(payload);
      if (Buffer.byteLength(json, 'utf8') > PADDED_PAYLOAD_BYTES) {
        throw new Error(
          `message does not fit one envelope: ${Buffer.byteLength(json, 'utf8')} bytes of ${PADDED_PAYLOAD_BYTES}`,
        );
      }

      const sealed = await sealedSenderEncryptMessage(
        padPayload(json),
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

  /* ---- groups ---- */

  /**
   * Creates a group and tells the members about it.
   *
   * The identifier is generated here and registered nowhere. There is no
   * request to the gateway in this method beyond the ordinary message sends,
   * because a group is not a thing the gateway has: it is a shared secret
   * label that a handful of clients agree to put inside their ciphertext.
   */
  async createGroup(name: string, memberAcis: string[]): Promise<GroupState> {
    const members = [...new Set([this.aci, ...memberAcis])];
    if (members.length > MAX_GROUP_MEMBERS) {
      throw new Error(`a group may hold at most ${MAX_GROUP_MEMBERS} members`);
    }
    if (name.length === 0 || name.length > GROUP_NAME_MAX) {
      throw new Error(`a group name must be 1-${GROUP_NAME_MAX} characters`);
    }

    const groupId = b64(randomBytes(GROUP_ID_BYTES));
    const group: GroupState = { groupId, name, members, revision: 1 };
    this.saveGroup(group);
    await this.announceGroup(group);
    return group;
  }

  /** Every group this device knows about. */
  groups(): GroupState[] {
    const index = this.store.getMetaString(GROUP_INDEX);
    if (!index) return [];
    const ids = JSON.parse(index) as string[];
    return ids.map((id) => this.group(id)).filter((g): g is GroupState => g !== null);
  }

  group(groupId: string): GroupState | null {
    const raw = this.store.getMetaString(groupMeta(groupId));
    return raw ? (JSON.parse(raw) as GroupState) : null;
  }

  /**
   * Sends to every member except this device.
   *
   * One padded envelope per member, because the gateway cannot fan a message
   * out to people it is not allowed to know about. That is the cost of the
   * property, and it is why the member cap exists.
   *
   * Deliberately not a single ciphertext shared between members: each envelope
   * is its own ratchet step with its own forward secrecy, so removing somebody
   * from a group removes their ability to read the next message immediately,
   * with no key rotation to remember and no window in which a removed member
   * can still decrypt.
   */
  async sendToGroup(groupId: string, body: string): Promise<void> {
    const group = this.group(groupId);
    if (!group) throw new Error(`unknown group ${groupId}`);
    await this.fanOut(group, body, undefined);
  }

  /** Adds or removes members and tells everyone, old and new. */
  async updateGroupMembers(groupId: string, members: string[]): Promise<GroupState> {
    const existing = this.group(groupId);
    if (!existing) throw new Error(`unknown group ${groupId}`);
    const next = [...new Set([this.aci, ...members])];
    if (next.length > MAX_GROUP_MEMBERS) {
      throw new Error(`a group may hold at most ${MAX_GROUP_MEMBERS} members`);
    }

    // A group that has reached the ceiling can no longer be edited, and saying
    // so is the whole point: silently emitting a revision the other
    // implementation reads back negative is how the group froze in the first
    // place.
    if (existing.revision >= MAX_GROUP_REVISION) {
      throw new Error(`group ${groupId} has reached the revision ceiling of ${MAX_GROUP_REVISION}`);
    }
    const updated: GroupState = { ...existing, members: next, revision: existing.revision + 1 };
    this.saveGroup(updated);

    // Told to the union of both lists. Somebody just removed still receives
    // the notice that they were, which is information they are entitled to and
    // which their client needs in order to stop showing the group as live.
    const audience = [...new Set([...existing.members, ...next])];
    await this.announceGroup(updated, audience);
    return updated;
  }

  /** Leaves a group and tells the others, then forgets it locally. */
  async leaveGroup(groupId: string): Promise<void> {
    const group = this.group(groupId);
    if (!group) return;
    const remaining = group.members.filter((m) => m !== this.aci);
    await this.fanOut(
      { ...group, members: remaining, revision: group.revision + 1 },
      'left',
      { name: group.name, members: remaining, event: 'leave', revision: group.revision + 1 },
      remaining,
    );
    this.forgetGroup(groupId, group.revision + 1);
  }

  private async announceGroup(group: GroupState, audience?: string[]): Promise<void> {
    await this.fanOut(
      group,
      `joined ${group.name}`,
      { name: group.name, members: group.members, event: 'update', revision: group.revision },
      audience,
    );
  }

  private async fanOut(
    group: GroupState,
    body: string,
    control: MessagePayload['group'],
    audience?: string[],
  ): Promise<void> {
    const targets = (audience ?? group.members).filter((m) => m !== this.aci);
    // Sent one at a time rather than in parallel. Every send mutates a ratchet
    // and the queue that serialises them is per-client, so firing fifty at
    // once would simply contend for it; worse, a partial failure would be
    // harder to reason about than a clean stop at the member it failed on.
    for (const member of targets) {
      await this.sendPayload(member, body, group.groupId, control);
    }
  }

  /**
   * Merges a group description that arrived from another member.
   *
   * A warning worth writing down: there is no server-side record of who is in
   * a group, so this is the only source of truth, and it arrives from a peer.
   * A dishonest member can therefore claim any membership they like, and every
   * client will believe them. That is a real limit of a design with no
   * authority to appeal to; closing it needs group changes signed by the
   * member who made them and verified against the group's history, which this
   * does not yet do. Until then the UI must show membership changes plainly so
   * a person can notice one they did not expect.
   *
   * Revisions only ever move forward, so a replayed old announcement cannot
   * quietly restore a member who was removed.
   */
  private applyGroupUpdate(
    groupId: string,
    update: NonNullable<MessagePayload['group']>,
    from: string,
  ): void {
    const existing = this.group(groupId);
    if (existing && update.revision <= existing.revision) return;

    // Only somebody already in the group may change it, once we know of one.
    if (existing && !existing.members.includes(from)) return;

    // A group we have left or been removed from leaves a tombstone behind, and
    // the tombstone is what keeps replay protection alive after the state it
    // protected is gone.
    //
    // Without it the attack is: remove somebody, wait for their client to
    // forget the group, then replay the original announcement. It arrives with
    // no existing state to compare against, so neither the revision check nor
    // the membership check above can fire, and the group comes back — with
    // whatever member list the replayer chose. The victim then sends group
    // messages to people the real owner never added. Found by replaying a
    // revision-1 announcement at a removed member; it worked.
    const tombstone = this.store.getMetaNumber(groupTombstone(groupId));
    if (!existing && tombstone !== null && update.revision <= tombstone) return;

    // An announcement from somebody who is not in the membership they are
    // announcing is nonsense, and it is how a stranger would introduce a group
    // built around a list of their choosing.
    if (!update.members.includes(from) && update.event !== 'leave') return;

    if (update.event === 'leave') {
      // A leave asserts one thing — the sender is gone — and is not an
      // announcement about the group. Treating it as one is what let a
      // stranger write a group onto this device: against an unknown groupId
      // there is no `existing`, so neither the revision check nor the
      // membership check above can fire, the exception on the line above skips
      // the last guard, and this branch then saved whatever name, roster and
      // revision arrived. The author needed no relationship to the group at
      // all; any registered account can send a sealed message.
      //
      // So a leave may only ever subtract its sender from a group we already
      // hold. Every other field comes from our own copy rather than from the
      // message, which also stops a real member rewriting the roster or
      // renaming the group on their way out.
      if (!existing) return;
      if (!existing.members.includes(from)) return;
      this.saveGroup({
        groupId,
        name: existing.name,
        members: existing.members.filter((m) => m !== from),
        revision: update.revision,
      });
      return;
    }

    if (!update.members.includes(this.aci)) {
      // We are no longer in it. Drop it rather than keep a group we cannot
      // send to and will never receive from again.
      this.forgetGroup(groupId);
      return;
    }

    // A group we have never seen is the only kind that grows this store, and
    // anybody who knows an account identifier can announce one. Without a
    // ceiling that is a device-filling attack from a single account: every
    // fresh identifier is another entry, and the index holding them is
    // rewritten on each save. Updates to groups already held are unaffected, so
    // reaching the cap cannot cost somebody a group they are really in.
    if (!existing && this.groups().length >= MAX_GROUPS) return;

    this.saveGroup({ groupId, name: update.name, members: update.members, revision: update.revision });
  }

  private saveGroup(group: GroupState): void {
    this.store.setMetaString(groupMeta(group.groupId), JSON.stringify(group));
    const ids = new Set(JSON.parse(this.store.getMetaString(GROUP_INDEX) ?? '[]') as string[]);
    ids.add(group.groupId);
    this.store.setMetaString(GROUP_INDEX, JSON.stringify([...ids]));
  }

  private forgetGroup(groupId: string, revision?: number): void {
    // Remember how far this group had got, so a replayed older announcement
    // cannot resurrect it. Cheap: one integer per group ever left.
    const last = revision ?? this.group(groupId)?.revision;
    if (last !== undefined) {
      const prior = this.store.getMetaNumber(groupTombstone(groupId)) ?? -1;
      if (last > prior) this.store.setMetaNumber(groupTombstone(groupId), last);
    }
    this.store.setMetaString(groupMeta(groupId), '');
    const ids = (JSON.parse(this.store.getMetaString(GROUP_INDEX) ?? '[]') as string[])
      .filter((id) => id !== groupId);
    this.store.setMetaString(GROUP_INDEX, JSON.stringify(ids));
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

      if (parsed.data.groupId && parsed.data.group) {
        this.applyGroupUpdate(parsed.data.groupId, parsed.data.group, senderAci);
      }

      return {
        senderAci,
        senderDeviceId: result.deviceId(),
        body: parsed.data.body,
        senderUsername: parsed.data.username ?? null,
        sentAt: parsed.data.sentAt,
        receivedAt: Date.now(),
        groupId: parsed.data.groupId ?? null,
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
      const mismatched = untrustedSender(error);
      if (mismatched !== null) this.onIdentityMismatch?.(mismatched);
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
   * Called when an envelope arrives from a contact whose pinned identity key no
   * longer matches, with that contact's account identifier.
   *
   * Named and shaped to match the Android client exactly. It previously handed
   * back the envelope instead, which says an identity changed without saying
   * whose — leaving the caller unable to mark the conversation it belongs to.
   */
  onIdentityMismatch: ((senderAci: string) => void) | undefined;

  private get cursor(): number {
    return this.store.getMetaNumber(META_CURSOR) ?? 0;
  }

  private enqueue(
    envelopes: StoredEnvelope[],
    onMessage: (message: IncomingMessage) => void | Promise<void>,
  ): Promise<void> {
    this.queue = this.queue.then(async () => {
      // Sorted here, because the order of this list is chosen by the gateway
      // and a hostile one is inside the threat model.
      //
      // The cursor moves to each envelope's seq as it is handled, and anything
      // at or below the cursor is skipped. Taken in the order they arrived,
      // one envelope carrying a high seq therefore steps the cursor past every
      // envelope behind it, which are then dropped without a word. Returning a
      // genuine batch in reverse was enough to lose four messages out of five;
      // a single unopenable envelope claiming seq 999999 — which costs the
      // gateway nothing to invent — stepped the cursor beyond every message
      // that account would ever be sent, permanently, from one response.
      //
      // Sorting makes the traversal independent of the order the gateway chose,
      // so nothing behind a later envelope can be skipped. It does not stop a
      // fabricated seq from poisoning the cursor for future messages: the
      // sequence numbers are the gateway's own and the client has no way to
      // check them. What it does do is confine the damage to what has not
      // arrived yet, rather than also destroying mail already in hand.
      const ordered = [...envelopes].sort((a, b) => a.seq - b.seq);
      for (const envelope of ordered) {
        const cursor = this.cursor;
        if (envelope.seq <= cursor) continue;
        // No single step may carry the cursor more than one window forward.
        // Ignored rather than refused: refusing would stall catch-up for good,
        // because the next poll returns the same poisoned entry, while skipping
        // it lets every genuine envelope beside it through and leaves the
        // cursor where those put it.
        //
        // Measured against the cursor as it stands for each envelope, not once
        // per batch, so that this matches consume() on the Kotlin side exactly.
        // A client that is genuinely far behind still walks forward through a
        // sparse range; only a jump is refused.
        if (envelope.seq > cursor + MAX_CURSOR_ADVANCE) continue;
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
        void this.rotatePreKeys();
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
  /**
   * Replaces the signed and Kyber prekeys once they are old enough.
   *
   * The gateway has always accepted these — the replenish request has fields
   * for both and verifies their signatures — but nothing ever sent them, so a
   * pair generated at registration was served for the life of the account. See
   * PREKEY_ROTATION_MS for what that costs.
   *
   * The key being replaced is kept. Someone may have fetched a bundle moments
   * before this ran, and the session they open with it names the old key;
   * deleting it immediately would make that first message undecryptable, and
   * an undecryptable message is dropped in silence here by design. The one
   * before it is dropped, so exactly two generations are ever held.
   */
  async rotatePreKeys(now = Date.now()): Promise<void> {
    const rotatedAt = this.store.getMetaNumber(META_PREKEYS_ROTATED_AT) ?? 0;
    if (now - rotatedAt < PREKEY_ROTATION_MS) return;

    const currentSigned = this.store.getMetaNumber(META_SIGNED_PREKEY_ID) ?? 1;
    const currentKyber = this.store.getMetaNumber(META_KYBER_PREKEY_ID) ?? 1;
    const nextSigned = currentSigned + 1;
    const nextKyber = currentKyber + 1;
    if (nextSigned > MAX_PREKEY_ID || nextKyber > MAX_PREKEY_ID) return;

    // Reserved before the keys exist, for the same reason the one-time
    // identifiers are: an upload that lands without the counter following it
    // would have the next rotation overwrite a private key the gateway is
    // still handing the public half of.
    this.store.setMetaNumber(META_SIGNED_PREKEY_ID, nextSigned);
    this.store.setMetaNumber(META_KYBER_PREKEY_ID, nextKyber);

    const signedPreKey = await generateSignedPreKey(this.identity, nextSigned, this.stores);
    const kyberPreKey = await generateKyberPreKey(this.identity, nextKyber, this.stores);
    await this.transport.replenishKeys({ signedPreKey, kyberPreKey });
    this.store.setMetaNumber(META_PREKEYS_ROTATED_AT, now);

    if (currentSigned > 1) this.store.deleteRecord('signed_prekeys', currentSigned - 1);
    if (currentKyber > 1) this.store.deleteRecord('kyber_prekeys', currentKyber - 1);
  }

  async replenishPreKeys(): Promise<void> {
    try {
      const remaining = await this.transport.remainingOneTimePreKeys();
      if (remaining > ONE_TIME_PREKEY_LOW_WATER) return;

      const firstId = this.store.getMetaNumber(META_NEXT_PREKEY_ID) ?? ONE_TIME_PREKEY_BATCH + 1;
      const count = ONE_TIME_PREKEY_BATCH - remaining;

      // Reserved before the keys exist, not after they are uploaded.
      //
      // Advancing afterwards leaves a window: if the upload lands and the
      // counter write does not — a crash, a killed process — the next
      // replenishment generates fresh keys under the same identifiers and
      // overwrites the private halves. The gateway then hands out a public
      // prekey whose private key is gone, and the session opened with it fails
      // to decrypt. That failure is indistinguishable from an envelope meant
      // for someone else, so the message is dropped in silence.
      //
      // Burning identifiers costs nothing: they are 24 bits, and a hundred at a
      // time is a hundred and sixty thousand batches before the space matters.
      this.store.setMetaNumber(META_NEXT_PREKEY_ID, firstId + count);

      const generated = await generateOneTimePreKeys(firstId, count, this.stores);
      await this.transport.replenishKeys({ oneTimePreKeys: generated });
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
 * The sender an identity mismatch names, or null if this was any other failure.
 *
 * libsignal reports the mismatch with a typed error code rather than a message
 * string, so this does not depend on wording that could change, and the error
 * carries the address it refused.
 */
function untrustedSender(error: unknown): string | null {
  if (!LibSignalErrorBase.is(error, ErrorCode.UntrustedIdentity)) return null;
  // The typed error declares this as the address it refused, which for our
  // addresses is the account identifier.
  return error.addr;
}
