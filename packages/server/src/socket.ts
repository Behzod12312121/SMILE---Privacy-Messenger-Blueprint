import type { Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocket, WebSocketServer } from 'ws';
import type { ServerToClient, StoredEnvelope } from '@millygram/protocol';
import type { Authenticator } from './auth.js';
import type { Store } from './db.js';
import type { DeliveryHub } from './app.js';

const HEARTBEAT_MS = 30_000;

/**
 * One account should not be able to pin unbounded memory by opening sockets in
 * a loop. A person has a handful of devices; anything beyond this is either a
 * bug or an attempt to exhaust the relay.
 */
const MAX_SOCKETS_PER_ACCOUNT = 8;

/**
 * How much undelivered traffic may pile up for one socket before it is dropped.
 *
 * Writing to a peer that has stopped reading does not fail, it queues, and the
 * queue is the relay's memory. Every member of a bucket receives every envelope
 * sent to it, so a client that connects and then never reads is served a copy
 * of all of that and holds it — and a client can generate the traffic itself.
 * Dropping the socket is safe because live delivery is not the only path: the
 * client reconnects and asks for everything since its cursor, so nothing is
 * lost by cutting a feed nobody is draining.
 *
 * Not covered by a test, and the attempt is worth recording: over loopback the
 * kernel absorbed several megabytes before `bufferedAmount` moved at all, so no
 * practical amount of traffic made it trigger there. On a real network, where a
 * stalled handset has far less buffer to hide behind, it does. The threshold is
 * configurable so an operator can lower it if this proves too slow to bite.
 */
const DEFAULT_MAX_BUFFERED_BYTES = 512 * 1024;

interface Connection {
  socket: WebSocket;
  alive: boolean;
}

/**
 * Live delivery, broadcast to a bucket. Every member of a bucket receives every
 * envelope sent to it and discards what they cannot decrypt, so the relay never
 * learns which one an envelope was for. There are no acknowledgements: an ack
 * would give that away immediately.
 */
export class SocketHub implements DeliveryHub {
  private readonly wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
  private readonly buckets = new Map<number, Set<Connection>>();
  /** Open socket count per account, so one account cannot exhaust the relay. */
  private readonly perAccount = new Map<string, number>();
  private readonly heartbeat: NodeJS.Timeout;

  constructor(
    private readonly store: Store,
    private readonly authenticator: Authenticator,
    private readonly maxBufferedBytes: number = DEFAULT_MAX_BUFFERED_BYTES,
  ) {
    this.heartbeat = setInterval(() => this.pingAll(), HEARTBEAT_MS);
    this.heartbeat.unref();
  }

  attach(server: Server): void {
    server.on('upgrade', (request, socket: Duplex, head) => {
      if (!(request.url ?? '').startsWith('/v1/socket')) return this.reject(socket, 404);

      // The token travels in a header rather than the query string: URLs get
      // written to access logs and proxy caches, and a bearer token in a log is
      // a bearer token that has leaked.
      const header = request.headers.authorization;
      const caller = header?.startsWith('Bearer ')
        ? this.authenticator.verifyToken(header.slice('Bearer '.length))
        : null;
      if (!caller) return this.reject(socket, 401);

      const account = this.store.accountByAci(caller.aci);
      if (!account) return this.reject(socket, 401);

      const open = this.perAccount.get(caller.aci) ?? 0;
      if (open >= MAX_SOCKETS_PER_ACCOUNT) return this.reject(socket, 429);

      this.wss.handleUpgrade(request, socket, head, (ws) =>
        this.accept(ws, account.bucket_id, caller.aci),
      );
    });
  }

  private reject(socket: Duplex, status: number): void {
    socket.write(`HTTP/1.1 ${status} ${status === 401 ? 'Unauthorized' : 'Not Found'}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
  }

  private accept(socket: WebSocket, bucketId: number, aci: string): void {
    const connection: Connection = { socket, alive: true };

    let members = this.buckets.get(bucketId);
    if (!members) {
      members = new Set();
      this.buckets.set(bucketId, members);
    }
    members.add(connection);
    this.perAccount.set(aci, (this.perAccount.get(aci) ?? 0) + 1);

    socket.on('pong', () => {
      connection.alive = true;
    });

    let released = false;
    const cleanup = (): void => {
      // Both 'close' and 'error' can fire for one socket, and decrementing
      // twice would let an account creep past its connection cap.
      if (released) return;
      released = true;

      members.delete(connection);
      if (members.size === 0) this.buckets.delete(bucketId);

      const remaining = (this.perAccount.get(aci) ?? 1) - 1;
      if (remaining <= 0) this.perAccount.delete(aci);
      else this.perAccount.set(aci, remaining);
    };
    socket.on('close', cleanup);
    socket.on('error', cleanup);

    this.send(socket, { type: 'caught-up' });
  }

  notify(bucketId: number, envelope: StoredEnvelope): void {
    const members = this.buckets.get(bucketId);
    if (!members) return;
    for (const connection of members) this.send(connection.socket, { type: 'envelope', envelope });
  }

  private send(socket: WebSocket, message: ServerToClient): void {
    if (socket.readyState !== WebSocket.OPEN) return;
    if (socket.bufferedAmount > this.maxBufferedBytes) {
      socket.terminate();
      return;
    }
    socket.send(JSON.stringify(message));
  }

  private pingAll(): void {
    for (const members of this.buckets.values()) {
      for (const connection of members) {
        if (!connection.alive) {
          connection.socket.terminate();
          continue;
        }
        connection.alive = false;
        connection.socket.ping();
      }
    }
  }

  async close(): Promise<void> {
    clearInterval(this.heartbeat);
    for (const members of this.buckets.values()) {
      for (const connection of members) connection.socket.close(1001, 'server shutting down');
    }
    this.buckets.clear();
    await new Promise<void>((resolve) => this.wss.close(() => resolve()));
  }
}
