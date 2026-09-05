import { pathToFileURL } from 'node:url';
import { b64 } from '@millygram/protocol';
import { buildApp } from './app.js';
import { Authenticator } from './auth.js';
import { loadConfig, type ServerConfig } from './config.js';
import { Store } from './db.js';
import { ServerIdentity } from './identity.js';
import { SocketHub } from './socket.js';

export { Store } from './db.js';
export { startObliviousRelay, createObliviousRelay, RELAY_USER_AGENT } from './oblivious-relay.js';
export type { ObliviousRelayOptions, RunningRelay } from './oblivious-relay.js';
export { loadConfig, DEFAULT_RATE_LIMITS } from './config.js';
export type { ServerConfig, RateLimits, Bucket } from './config.js';


export interface RunningServer {
  url: string;
  trustRoot: string;
  store: Store;
  close(): Promise<void>;
}

export async function startServer(overrides: Partial<ServerConfig> = {}): Promise<RunningServer> {
  const config = loadConfig(overrides);
  const store = new Store(config.databasePath);
  const identity = ServerIdentity.load(store);
  const authenticator = new Authenticator(store, identity, config.authTokenTtlMs);
  const hub = new SocketHub(store, authenticator);
  const app = buildApp({ config, store, identity, authenticator, hub });

  const sweep = setInterval(() => {
    store.sweepEnvelopes(config.envelopeTtlMs);
    store.sweepChallenges();
  }, config.sweepIntervalMs);
  sweep.unref();

  await app.listen({ host: config.host, port: config.port });
  hub.attach(app.server);

  const address = app.server.address();
  const port = typeof address === 'object' && address ? address.port : config.port;

  return {
    url: `http://${config.host}:${port}`,
    trustRoot: b64(identity.trustRootPublic.serialize()),
    store,
    async close() {
      clearInterval(sweep);
      await hub.close();
      await app.close();
      store.close();
    },
  };
}

/**
 * Whether this module was run directly rather than imported.
 *
 * The hand-rolled version of this check built `file://` + a slash-swapped path,
 * which produces `file://C:/...` on Windows while `import.meta.url` is
 * `file:///C:/...` — three slashes against two. The comparison never matched,
 * so `npm run relay` started nothing and exited 0, and no test caught it
 * because every test starts the server in-process through `startServer()`.
 *
 * `pathToFileURL` is the function that knows how to do this on every platform.
 */
const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  const server = await startServer();
  process.stdout.write(`millygram relay listening on ${server.url}\ntrust root: ${server.trustRoot}\n`);

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      void server.close().then(() => process.exit(0));
    });
  }
}
