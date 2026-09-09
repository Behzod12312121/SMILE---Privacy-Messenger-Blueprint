import { pathToFileURL } from 'node:url';
import { b64 } from '@millygram/protocol';
import { type RecoveryCodeSender, buildApp } from './app.js';
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
export { DEFAULT_INBOUND_POW_ESCALATION } from './config.js';


export interface RunningServer {
  url: string;
  trustRoot: string;
  store: Store;
  close(): Promise<void>;
}

export interface ServerOverrides extends Partial<ServerConfig> {
  /** See RecoveryCodeSender. Without one, recovery codes go nowhere. */
  sendRecoveryCode?: RecoveryCodeSender;
}

export async function startServer(overrides: ServerOverrides = {}): Promise<RunningServer> {
  const config = loadConfig(overrides);
  const store = new Store(config.databasePath);
  const identity = ServerIdentity.load(store);
  const authenticator = new Authenticator(store, identity, config.authTokenTtlMs);
  const hub = new SocketHub(store, authenticator, config.maxSocketBufferBytes);
  const app = buildApp({
    config,
    store,
    identity,
    authenticator,
    hub,
    ...(overrides.sendRecoveryCode ? { sendRecoveryCode: overrides.sendRecoveryCode } : {}),
  });

  const sweep = setInterval(() => {
    store.sweepEnvelopes(config.envelopeTtlMs);
    store.sweepChallenges();
    store.sweepRecoveryCodes();
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
 * Where recovery codes actually go.
 *
 * The gateway refuses to guess. Without one of these set, `startServer` logs an
 * error on every request and drops the code, because a recovery route that
 * accepts everything and delivers nothing looks healthy from the outside while
 * being entirely broken for the only person who needs it.
 *
 * `MG_RECOVERY_SMS_URL` is the production path: every SMS aggregator in this
 * market takes an HTTP POST, so the shape is a POST of `{phoneNumber, code}`
 * with an optional bearer token, and adapting it to a specific provider is a
 * change to one function rather than to the gateway.
 *
 * `MG_RECOVERY_CODE_STDOUT` is for development and prints the code to the
 * console. It is deliberately not the fallback and never the default: anyone
 * who can read the log could then take over any account with a number attached.
 * It announces itself loudly at startup so it cannot be left on by accident.
 */
function configureRecoverySender(): RecoveryCodeSender | undefined {
  const url = process.env['MG_RECOVERY_SMS_URL'];
  if (url !== undefined && url !== '') {
    const token = process.env['MG_RECOVERY_SMS_TOKEN'];
    return async (phoneNumber, code) => {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(token !== undefined && token !== '' ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ phoneNumber, code }),
      });
      // Thrown, not swallowed: /v1/recovery/start awaits this, and a failure
      // the user never hears about leaves them waiting for a code that is not
      // coming.
      if (!response.ok) throw new Error(`recovery sms gateway returned ${response.status}`);
    };
  }

  if (process.env['MG_RECOVERY_CODE_STDOUT'] === '1') {
    process.stderr.write(
      'WARNING: MG_RECOVERY_CODE_STDOUT is set. Recovery codes are printed to this ' +
        'console, so anyone who can read it can take over any account with a number ' +
        'attached. Never set this in production.\n',
    );
    return (phoneNumber, code) => {
      process.stdout.write(`recovery code for ${phoneNumber}: ${code}\n`);
    };
  }

  return undefined;
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
  const sender = configureRecoverySender();
  const server = await startServer(sender ? { sendRecoveryCode: sender } : {});
  process.stdout.write(`millygram relay listening on ${server.url}\ntrust root: ${server.trustRoot}\n`);

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      void server.close().then(() => process.exit(0));
    });
  }
}
