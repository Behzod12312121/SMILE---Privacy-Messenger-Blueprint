import { pathToFileURL } from 'node:url';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { OBLIVIOUS_REQUEST_BYTES } from '@millygram/protocol';

/**
 * The oblivious relay. It is the only component that sees a sender's address,
 * and it is deliberately incapable of doing anything with it: the body it
 * forwards is sealed to the gateway's key, and it is operated by someone other
 * than whoever runs the gateway. Neither half alone links a sender to a bucket.
 *
 * Run this as its own process, under its own operator. Running it beside the
 * gateway would make the whole arrangement theatre.
 */

/** Sealed request plus HPKE overhead, with a little slack. Anything larger is not ours. */
const MAX_BODY_BYTES = OBLIVIOUS_REQUEST_BYTES + 256;
const UPSTREAM_TIMEOUT_MS = 10_000;

/** The gateway answers with a status and, at most, a short JSON error. */
const MAX_UPSTREAM_BYTES = 4096;
const ALLOWED_UPSTREAM_STATUS = new Set([202, 400, 404, 409, 413, 429]);

/**
 * This relay is the most exposed component in the system: it takes
 * unauthenticated requests from anyone, by design, because authenticating them
 * would defeat its purpose. That makes it the obvious thing to flood, and the
 * gateway's own limits do not protect the relay's sockets or the operator's
 * bandwidth bill.
 *
 * Limiting here is awkward on purpose. Keying on the client address would build
 * exactly the record of who submitted and when that this component exists not
 * to keep, so the limit is global: a single ceiling on requests in flight
 * through the relay, holding no per-client state at all.
 */
const MAX_REQUESTS_PER_SECOND = 200;
const MAX_CONCURRENT_UPSTREAM = 64;

/**
 * Pinned rather than left to the HTTP client, which stamps its own by default.
 * Every request this relay makes must look identical, so that nothing about the
 * upstream request varies with the client that caused it.
 */
export const RELAY_USER_AGENT = 'millygram-oblivious-relay';

export interface ObliviousRelayOptions {
  gatewayUrl: string;
  host?: string;
  port?: number;
}

export interface RunningRelay {
  url: string;
  close(): Promise<void>;
}

function readBody(request: IncomingMessage): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;

    request.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        resolve(null);
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', () => resolve(null));
  });
}

/**
 * A global token bucket and an in-flight counter. Both hold a number and
 * nothing else — no addresses, no identifiers, nothing that could later be
 * asked for.
 */
class GlobalThrottle {
  private tokens = MAX_REQUESTS_PER_SECOND;
  private updatedAt = Date.now();
  private inFlight = 0;

  admit(): boolean {
    const now = Date.now();
    this.tokens = Math.min(
      MAX_REQUESTS_PER_SECOND,
      this.tokens + ((now - this.updatedAt) / 1000) * MAX_REQUESTS_PER_SECOND,
    );
    this.updatedAt = now;

    if (this.tokens < 1 || this.inFlight >= MAX_CONCURRENT_UPSTREAM) return false;
    this.tokens -= 1;
    this.inFlight += 1;
    return true;
  }

  release(): void {
    this.inFlight = Math.max(0, this.inFlight - 1);
  }
}

async function handle(
  request: IncomingMessage,
  response: ServerResponse,
  gatewayUrl: string,
  throttle: GlobalThrottle,
): Promise<void> {
  if (request.method !== 'POST' || request.url !== '/') {
    response.writeHead(404).end();
    return;
  }

  if (!throttle.admit()) {
    response.writeHead(429).end();
    return;
  }

  try {
    await forward(request, response, gatewayUrl);
  } finally {
    throttle.release();
  }
}

async function forward(
  request: IncomingMessage,
  response: ServerResponse,
  gatewayUrl: string,
): Promise<void> {
  const body = await readBody(request);
  if (!body || body.length === 0) {
    response.writeHead(413).end();
    return;
  }

  try {
    // Exactly one header goes upstream. No Forwarded, no X-Forwarded-For, no
    // User-Agent, no cookie, nothing carried over from the client request —
    // forwarding any of them would hand the gateway the address this component
    // exists to withhold. Redirects are refused rather than followed, so the
    // gateway cannot point this relay at a destination of its choosing.
    const upstream = await fetch(new URL('/v1/oblivious', gatewayUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', 'user-agent': RELAY_USER_AGENT },
      body: new Uint8Array(body),
      redirect: 'error',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });

    const payload = Buffer.from(await upstream.arrayBuffer());
    if (payload.length > MAX_UPSTREAM_BYTES) {
      response.writeHead(502).end();
      return;
    }

    // The status and content type are pinned rather than echoed. Both are
    // values the gateway controls, and this component is deliberately operated
    // by someone who does not fully trust it — a hostile or compromised
    // gateway should not get to choose bytes that this relay writes into a
    // response header. An unexpected status is reported as a plain 502.
    const status = ALLOWED_UPSTREAM_STATUS.has(upstream.status) ? upstream.status : 502;
    response.writeHead(status, {
      'content-type': 'application/octet-stream',
      'content-length': payload.length,
    });
    response.end(payload);
  } catch {
    response.writeHead(502).end();
  }
}

export function createObliviousRelay(options: ObliviousRelayOptions): Server {
  // No logger is installed anywhere in this file, deliberately. An access log
  // here would be a record of who submitted and when, which is the one thing
  // this component must never keep.
  const throttle = new GlobalThrottle();
  return createServer((request, response) => {
    void handle(request, response, options.gatewayUrl, throttle);
  });
}

export async function startObliviousRelay(options: ObliviousRelayOptions): Promise<RunningRelay> {
  const host = options.host ?? '127.0.0.1';
  const server = createObliviousRelay(options);

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 8444, host, resolve);
  });

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : (options.port ?? 8444);

  return {
    url: `http://${host}:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        // Clients keep sockets alive between submissions, and an idle keep-alive
        // socket will hold close() open indefinitely.
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

/** See the note in index.ts: the hand-rolled form of this never matched on Windows. */
const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  const gatewayUrl = process.env.MG_GATEWAY_URL;
  if (!gatewayUrl) {
    process.stderr.write('MG_GATEWAY_URL is required (the MillyGram relay this forwards to)\n');
    process.exit(1);
  }

  const relay = await startObliviousRelay({
    gatewayUrl,
    host: process.env.MG_RELAY_HOST ?? '127.0.0.1',
    port: Number.parseInt(process.env.MG_RELAY_PORT ?? '8444', 10),
  });

  process.stdout.write(`oblivious relay listening on ${relay.url}\nforwarding to ${gatewayUrl}\n`);

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      void relay.close().then(() => process.exit(0));
    });
  }
}
