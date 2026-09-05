import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { MillygramClient, type IncomingMessage } from '@millygram/client';
import { startObliviousRelay, startServer, Store } from '@millygram/server';

const workdir = mkdtempSync(join(tmpdir(), 'millygram-demo-'));
const serverDb = join(workdir, 'relay.db');

/** Appears in exactly one message, so the audit below is a search, not a claim. */
const CANARY = 'BUGUN-SOAT-10-DA-UCHRASHAMIZ-7f3a91';

function heading(title: string): void {
  process.stdout.write(`\n${'-'.repeat(70)}\n${title}\n${'-'.repeat(70)}\n`);
}

async function waitFor<T>(read: () => T | undefined, label: string, timeoutMs = 8000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = read();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await delay(25);
  }
}

const server = await startServer({ host: '127.0.0.1', port: 0, databasePath: serverDb });

// In production this is run by a different operator entirely. Here it is a
// second process on the same machine, which exercises the plumbing but proves
// none of the non-collusion the design depends on.
const oblivious = await startObliviousRelay({ gatewayUrl: server.url, host: '127.0.0.1', port: 0 });

process.stdout.write(
  `gateway listening on ${server.url}\noblivious relay on ${oblivious.url}\nworkdir ${workdir}\n`,
);

const common = { serverUrl: server.url };

heading('1. Registration');

const dilnoza = await MillygramClient.register({
  ...common,
  databasePath: join(workdir, 'dilnoza.db'),
  passphrase: 'correct horse battery staple',
  username: 'dilnoza_az',
  obliviousRelayUrl: oblivious.url,
});
const gayrat = await MillygramClient.register({
  ...common,
  databasePath: join(workdir, 'gayrat.db'),
  passphrase: 'a different passphrase entirely',
  username: 'gayrat',
});
const feruza = await MillygramClient.register({
  ...common,
  databasePath: join(workdir, 'feruza.db'),
  passphrase: 'third account third passphrase',
  username: 'feruza',
});

for (const client of [dilnoza, gayrat, feruza]) {
  process.stdout.write(`@${client.username.padEnd(11)} ${client.aci}  bucket ${client.bucketId}\n`);
}
process.stdout.write('no phone numbers were involved at any point\n');
process.stdout.write('dilnoza sends through the oblivious relay, so the gateway never sees her address\n');

heading('2. Live delivery, both directions');

const gayratInbox: IncomingMessage[] = [];
const dilnozaInbox: IncomingMessage[] = [];

await gayrat.connect((message) => {
  gayratInbox.push(message);
});
await dilnoza.connect((message) => {
  dilnozaInbox.push(message);
});

await dilnoza.send('gayrat', 'Salom! Ertaga soat 10 da uchrashamizmi?');
const first = await waitFor(() => gayratInbox[0], "Gʻayrat's first message");
process.stdout.write(`gayrat received: "${first.body}"\n`);
process.stdout.write(`  sender recovered from the sealed envelope: ${first.senderAci}\n`);
process.stdout.write(`  matches dilnoza: ${first.senderAci === dilnoza.aci}\n`);

await gayrat.send(dilnoza.aci, 'Ha, aynan shu vaqtda boʻladi.');
process.stdout.write(`dilnoza received: "${(await waitFor(() => dilnozaInbox[0], 'the reply')).body}"\n`);

await dilnoza.send('gayrat', 'Zoʻr, kutaman. Maʼlumotlarni oldindan yuboraman.');
process.stdout.write(`gayrat received: "${(await waitFor(() => gayratInbox[1], 'the follow-up')).body}"\n`);

heading('3. Safety numbers');

const fromDilnoza = await dilnoza.safetyNumber(gayrat.aci);
const fromGayrat = await gayrat.safetyNumber(dilnoza.aci);
process.stdout.write(`dilnoza computes: ${fromDilnoza}\n`);
process.stdout.write(`gayrat computes:  ${fromGayrat}\n`);
if (fromDilnoza !== fromGayrat) throw new Error('safety numbers disagree');
process.stdout.write('identical on both devices\n');

heading('4. A message for someone else in the same bucket');

await dilnoza.send('feruza', CANARY);
await waitFor(
  () => (server.store.since(feruza.bucketId, 0).length >= 4 ? true : undefined),
  'the envelope for feruza',
);
await delay(300);

const bucketTotal = server.store.since(gayrat.bucketId, 0).length;
process.stdout.write(`envelopes sitting in bucket ${gayrat.bucketId}: ${bucketTotal}\n`);
process.stdout.write(`messages gayrat could actually open:      ${gayratInbox.length}\n`);
process.stdout.write(
  `gayrat's client downloaded every one of them and silently discarded ${bucketTotal - gayratInbox.length}.\n` +
    'The relay cannot tell which member of the bucket any envelope was for.\n',
);

heading('5. Audit: what can the operator actually read?');

const audit = new Store(serverDb);

for (const table of audit.tableNames()) {
  const rows = audit.dumpTable(table);
  process.stdout.write(`\n${table} (${rows.length} row${rows.length === 1 ? '' : 's'})\n`);
  if (table === 'server_state') {
    process.stdout.write('  [server signing keys, withheld from this dump]\n');
    continue;
  }
  for (const row of rows.slice(0, 2)) {
    const rendered = Object.entries(row)
      .map(([column, value]) => {
        if (!Buffer.isBuffer(value)) return `${column}=${JSON.stringify(value)}`;
        // Public keys and signatures are public by design; only the envelope
        // body is ciphertext. Blurring that would be the same overclaiming this
        // project exists to avoid.
        return `${column}=<${value.length} bytes, ${column === 'content' ? 'ciphertext' : 'public material'}>`;
      })
      .join(' ');
    process.stdout.write(`  ${rendered}\n`);
  }
  if (rows.length > 2) process.stdout.write(`  ... ${rows.length - 2} more\n`);
}

const envelopes = audit.dumpTable('envelopes');
const envelopeColumns = Object.keys(envelopes[0] ?? {});
const sizes = new Set(envelopes.map((row) => (row.content as Buffer).length));
audit.close();

heading('6. Searching every byte the relay has written');

const targets = [serverDb, `${serverDb}-wal`, `${serverDb}-shm`].filter((path) => existsSync(path));
const needle = Buffer.from(CANARY, 'utf8');
let totalBytes = 0;
let hits = 0;

for (const path of targets) {
  const contents = readFileSync(path);
  totalBytes += contents.length;
  const found = contents.includes(needle);
  hits += found ? 1 : 0;
  process.stdout.write(`  ${path.split(/[\\/]/).pop()}: ${contents.length} bytes, canary present: ${found}\n`);
}

process.stdout.write(`\nsearched ${totalBytes} bytes across ${targets.length} files\n`);
process.stdout.write(`plaintext occurrences of the message: ${hits}\n`);
process.stdout.write(`envelope columns: ${envelopeColumns.join(', ')}\n`);
process.stdout.write(`a recipient column exists: ${envelopeColumns.some((c) => /aci|recipient|destination|sender/.test(c))}\n`);
process.stdout.write(`distinct envelope sizes on disk: ${[...sizes].sort((a, b) => a - b).join(', ')}\n`);

dilnoza.close();
gayrat.close();
feruza.close();
await oblivious.close();
await server.close();

if (hits > 0) {
  process.stderr.write('\nFAILED: message plaintext was found in relay storage\n');
  process.exit(1);
}

process.stdout.write(
  '\nThe relay stored these messages, delivered them, and knows neither who sent them\n' +
    'nor which of sixteen possible people each one was for.\n',
);
