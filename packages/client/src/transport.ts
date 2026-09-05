import { PublicKey } from '@signalapp/libsignal-client';
import { WebSocket } from 'ws';
import {
  AuthResponse,
  ChallengeResponse,
  DirectoryResponse,
  PreKeyBundleResponse,
  RegisterResponse,
  ServerToClient,
  OBLIVIOUS_INFO,
  authSigningPayload,
  b64,
  encodeObliviousRequest,
  solveProofOfWork,
  unb64,
  type Bytes,
  type RegisterRequest,
  type ReplenishRequest,
  type StoredEnvelope,
} from '@millygram/protocol';

export class TransportError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(`${code} (HTTP ${status})`);
    this.name = 'TransportError';
  }
}

export interface Credentials {
  aci: string;
  deviceId: number;
  sign(payload: Bytes): Bytes;
}

/** Tokens are refreshed a little early so a request never races its own expiry. */
const TOKEN_REFRESH_MARGIN_MS = 30_000;

export class Transport {
  private token: { value: string; expiresAt: number } | null = null;
  private socket: WebSocket | null = null;
  private obliviousKey: PublicKey | null = null;

  constructor(
    private readonly baseUrl: string,
    private credentials: Credentials | null = null,
    /** When set, submissions go through this relay instead of straight to the gateway. */
    private readonly obliviousRelayUrl: string | null = null,
  ) {}

  setCredentials(credentials: Credentials): void {
    this.credentials = credentials;
    this.token = null;
  }

  private async request(
    method: string,
    path: string,
    options: { body?: unknown; headers?: Record<string, string>; auth?: boolean } = {},
  ): Promise<unknown> {
    const headers: Record<string, string> = { ...options.headers };
    if (options.body !== undefined) headers['content-type'] = 'application/json';
    if (options.auth) headers.authorization = `Bearer ${await this.accessToken()}`;

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });

    if (response.status === 204) return null;

    const text = await response.text();
    const parsed: unknown = text ? JSON.parse(text) : null;

    if (!response.ok) {
      const code =
        typeof parsed === 'object' && parsed !== null && 'error' in parsed
          ? String((parsed as { error: unknown }).error)
          : 'request_failed';
      throw new TransportError(response.status, code);
    }
    return parsed;
  }

  async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt - TOKEN_REFRESH_MARGIN_MS > Date.now()) return this.token.value;
    if (!this.credentials) throw new Error('transport has no credentials');

    const { aci, deviceId, sign } = this.credentials;
    const challenge = ChallengeResponse.parse(
      await this.request('GET', `/v1/accounts/challenge?aci=${encodeURIComponent(aci)}`),
    );
    const nonce = unb64(challenge.nonce);
    const signature = sign(authSigningPayload(aci, deviceId, nonce));

    const auth = AuthResponse.parse(
      await this.request('POST', '/v1/accounts/auth', {
        body: { aci, deviceId, nonce: challenge.nonce, signature: b64(signature) },
      }),
    );

    this.token = { value: auth.token, expiresAt: auth.expiresAt };
    return auth.token;
  }

  async register(request: RegisterRequest): Promise<RegisterResponse> {
    return RegisterResponse.parse(await this.request('POST', '/v1/accounts', { body: request }));
  }

  async lookupUsername(username: string): Promise<DirectoryResponse> {
    return DirectoryResponse.parse(
      await this.request('GET', `/v1/directory/${encodeURIComponent(username)}`, { auth: true }),
    );
  }

  async fetchPreKeyBundle(aci: string): Promise<PreKeyBundleResponse> {
    return PreKeyBundleResponse.parse(
      await this.request('GET', `/v1/keys/${encodeURIComponent(aci)}`, { auth: true }),
    );
  }

  async replenishKeys(request: ReplenishRequest): Promise<void> {
    await this.request('PUT', '/v1/keys', { body: request, auth: true });
  }

  async remainingOneTimePreKeys(): Promise<number> {
    const result = (await this.request('GET', '/v1/keys/count', { auth: true })) as {
      oneTimePreKeys: number;
    };
    return result.oneTimePreKeys;
  }

  async fetchDeliveryCertificate(): Promise<{ certificate: string; expiresAt: number }> {
    return (await this.request('GET', '/v1/certificate/delivery', { auth: true })) as {
      certificate: string;
      expiresAt: number;
    };
  }

  /**
   * The gateway's public key, used to seal submissions so the oblivious relay
   * cannot read them. Fetched over the ordinary connection and cached in
   * memory. It is not pinned, and does not need to be: holding this key reveals
   * only what the gateway already sees legitimately — a bucket id, a proof of
   * work, and a ciphertext it cannot decrypt.
   */
  private async obliviousPublicKey(): Promise<PublicKey> {
    if (this.obliviousKey) return this.obliviousKey;
    const result = (await this.request('GET', '/v1/oblivious-key')) as { publicKey: string };
    this.obliviousKey = PublicKey.deserialize(unb64(result.publicKey));
    return this.obliviousKey;
  }

  /**
   * Carries no identity whatsoever: no token, no account, no header tied to a
   * person, and a bucket rather than a recipient. The proof of work is what
   * pays for the send, because there is nobody to bill.
   *
   * With an oblivious relay configured, the last identifier left — the client's
   * own address — is withheld from the gateway too.
   */
  async submit(bucketId: number, content: Uint8Array, difficulty: number): Promise<void> {
    const nonce = solveProofOfWork(bucketId, content, difficulty);

    if (!this.obliviousRelayUrl) {
      await this.request('PUT', '/v1/messages', { body: { bucketId, content: b64(content), nonce } });
      return;
    }

    const sealed = (await this.obliviousPublicKey()).seal(
      encodeObliviousRequest(bucketId, nonce, content),
      OBLIVIOUS_INFO,
    );

    const response = await fetch(this.obliviousRelayUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: sealed,
    });

    if (!response.ok) {
      const text = await response.text();
      let code = 'submission_failed';
      try {
        const parsed: unknown = text ? JSON.parse(text) : null;
        if (typeof parsed === 'object' && parsed !== null && 'error' in parsed) {
          code = String((parsed as { error: unknown }).error);
        }
      } catch {
        // The relay may answer with no body at all; the status is enough.
      }
      throw new TransportError(response.status, code);
    }
  }

  /** Everything the caller's bucket has received since `cursor`. */
  async since(cursor: number): Promise<StoredEnvelope[]> {
    const result = (await this.request('GET', `/v1/messages?since=${cursor}`, { auth: true })) as {
      envelopes: StoredEnvelope[];
    };
    return result.envelopes;
  }

  async connect(handlers: {
    onEnvelope(envelope: StoredEnvelope): void | Promise<void>;
    onCaughtUp?: () => void;
    onClose?: (code: number) => void;
  }): Promise<void> {
    const token = await this.accessToken();
    const url = `${this.baseUrl.replace(/^http/, 'ws')}/v1/socket`;
    const socket = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
    this.socket = socket;

    await new Promise<void>((resolve, reject) => {
      socket.once('open', resolve);
      socket.once('error', reject);
    });

    socket.on('message', (raw) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        return;
      }
      const message = ServerToClient.safeParse(parsed);
      if (!message.success) return;

      if (message.data.type === 'envelope') {
        void handlers.onEnvelope(message.data.envelope);
      } else {
        handlers.onCaughtUp?.();
      }
    });

    socket.on('close', (code) => {
      this.socket = null;
      handlers.onClose?.(code);
    });
  }

  disconnect(): void {
    this.socket?.close(1000, 'client closing');
    this.socket = null;
  }
}
