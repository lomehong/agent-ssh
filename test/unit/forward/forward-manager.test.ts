import { describe, it, expect, afterEach } from 'vitest';
import { createServer, connect, type Server } from 'node:net';
import { Duplex } from 'node:stream';
import { ForwardManager } from '../../../src/forward/forward-manager.js';

// Real sockets, fake SSH: the manager's own work is the TCP bookkeeping
// (listen, pair, teardown) around the channels ssh2 hands back, so the fake
// client answers forwardOut with an echo stream and the tests assert bytes
// actually cross a real loopback connection.

class EchoChannel extends Duplex {
  _write(chunk: Buffer, _enc: string, cb: (err?: Error | null) => void) {
    this.push(chunk); // echo
    cb();
  }
  _read() { /* all data pushed */ }
  close() { this.destroy(); }
}

class FakeClient {
  echo = true;
  forwardedOut: Array<[string, number, string, number]> = [];
  forwardInCalls: Array<[string, number]> = [];
  unforwardInCalls: Array<[string, number]> = [];
  handlers = new Map<string, Array<(...a: unknown[]) => void>>();

  forwardOut(srcIP: string, srcPort: number, dstIP: string, dstPort: number, cb: (err: Error | null, stream: Duplex) => void) {
    this.forwardedOut.push([srcIP, srcPort, dstIP, dstPort]);
    const stream = new EchoChannel();
    if (this.echo) stream.write(`BANNER-FROM-${dstIP}:${dstPort}\n`);
    process.nextTick(() => cb(null, stream));
  }

  forwardIn(addr: string, port: number, cb?: (err: Error | null, port?: number) => void) {
    this.forwardInCalls.push([addr, port]);
    cb?.(null, port);
  }

  unforwardIn(addr: string, port: number, cb?: () => void) {
    this.unforwardInCalls.push([addr, port]);
    cb?.();
  }

  on(event: string, handler: (...a: unknown[]) => void) {
    const list = this.handlers.get(event) ?? [];
    list.push(handler);
    this.handlers.set(event, list);
    return this;
  }

  emitEvent(event: string, ...args: unknown[]) {
    for (const h of this.handlers.get(event) ?? []) h(...args);
  }
}

function makeManager(allowDynamic = true) {
  const client = new FakeClient();
  const manager = new ForwardManager({
    profile: () => ({ } as never),
    getClient: () => client as never,
    allowDynamic: () => allowDynamic,
  });
  return { manager, client };
}

function readUntil(socket: { on: (e: string, cb: (b: Buffer) => void) => unknown }, needle: string, timeoutMs = 1000): Promise<string> {
  return new Promise((resolve, reject) => {
    let seen = '';
    const timer = setTimeout(() => reject(new Error(`timeout; seen: ${JSON.stringify(seen)}`)), timeoutMs);
    socket.on('data', (b: Buffer) => {
      seen += b.toString('utf8');
      if (seen.includes(needle)) {
        clearTimeout(timer);
        resolve(seen);
      }
    });
  });
}

let servers: Server[] = [];

afterEach(async () => {
  for (const s of servers) {
    // A half-open connection would hold server.close() past the hook timeout.
    (s as Server & { closeAllConnections?: () => void }).closeAllConnections?.();
    await new Promise<void>((r) => s.close(() => r()));
  }
  servers = [];
});

describe('ForwardManager', () => {
  it('local forward: a loopback connection crosses to the far-end stream and back', async () => {
    const { manager, client } = makeManager();
    const info = await manager.openLocal({ listenPort: 0, targetHost: 'db.internal', targetPort: 5432 });
    expect(info.listen).not.toContain(':0');
    const port = Number(info.listen.split(':')[1]);

    const socket = connect(port, '127.0.0.1');
    const seen = await readUntil(socket, 'BANNER-FROM-db.internal:5432');
    expect(seen).toContain('BANNER-FROM-db.internal:5432');
    // The far end saw the real target, not the loopback hop.
    expect(client.forwardedOut[0]?.[2]).toBe('db.internal');
    expect(client.forwardedOut[0]?.[3]).toBe(5432);
    socket.destroy();

    const closed = await manager.close(info.id);
    expect(closed.outcome).toBe('closed');
  });

  it('close destroys live connections', async () => {
    const { manager } = makeManager();
    const info = await manager.openLocal({ listenPort: 0, targetHost: 't', targetPort: 1 });
    const port = Number(info.listen.split(':')[1]);
    const socket = connect(port, '127.0.0.1');
    // Attach a consumer BEFORE closing: a paused socket with unread data holds
    // its teardown back, which would make this test measure Node backpressure
    // instead of the manager.
    const bannerSeen = readUntil(socket, 'BANNER');
    expect(await bannerSeen).toContain('BANNER');
    const portStillOpen = manager.close(info.id).then(() => {
      // Server side stopped listening: a fresh connect must be refused.
      return new Promise<boolean>((resolve) => {
        const probe = connect(port, '127.0.0.1');
        probe.once('error', () => resolve(false));
        probe.once('connect', () => { probe.destroy(); resolve(true); });
      });
    });
    const closed = await new Promise<boolean>((resolve) => {
      if (socket.destroyed) return resolve(true);
      socket.once('close', () => resolve(true));
      setTimeout(() => resolve(false), 500);
    });
    expect(closed).toBe(true);
    expect(await portStillOpen).toBe(false);
  });

  it('dynamic forward is refused unless explicitly enabled', async () => {
    const { manager } = makeManager(false);
    await expect(manager.openDynamic({ listenPort: 0 })).rejects.toThrow(/disabled/);
  });

  it('dynamic forward: SOCKS5 handshake parses CONNECT and routes to forwardOut', async () => {
    const { manager, client } = makeManager(true);
    const info = await manager.openDynamic({ listenPort: 0 });
    const port = Number(info.listen.split(':')[1]);

    const sock = connect(port, '127.0.0.1');
    // Greet with no-auth, then CONNECT 10.1.2.3:9999.
    sock.write(Buffer.from([0x05, 0x01, 0x00]));
    await readUntil(sock, '\x05\x00');
    sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x27, 0x0f]));
    const seen = await readUntil(sock, 'BANNER-FROM-10.1.2.3:9999');
    expect(seen).toContain('BANNER-FROM-10.1.2.3:9999');
    expect(client.forwardedOut[0]?.[2]).toBe('10.1.2.3');
    expect(client.forwardedOut[0]?.[3]).toBe(9999);
    sock.destroy();
    await manager.close(info.id);
  });

  it('remote forward registers forwardIn and cancels it on close', async () => {
    const { manager, client } = makeManager();
    const info = await manager.openRemote({ listenPort: 23456, targetHost: 't', targetPort: 80 });
    expect(client.forwardInCalls[0]).toEqual(['127.0.0.1', 23456]);
    await manager.close(info.id);
    expect(client.unforwardInCalls[0]).toEqual(['127.0.0.1', 23456]);
  });

  it('close on an unknown id reports not-found instead of throwing', async () => {
    const { manager } = makeManager();
    expect((await manager.close('f-local-999')).outcome).toBe('not-found');
  });

  it('remote forward: incoming dispatch matches the bound port and rejects the rest', async () => {
    // Data piping through a real ssh2 channel is covered by the integration
    // suite; a Duplex stub fights the half-close semantics that pipe depends
    // on, so here only the dispatch bookkeeping is asserted.
    const { manager, client } = makeManager();
    await manager.openRemote({ listenPort: 23457, targetHost: '127.0.0.1', targetPort: 80 });

    let rejectedUnknown = false;
    client.emitEvent('tcp connection', { destPort: 9999 }, () => ({}), () => { rejectedUnknown = true; });
    expect(rejectedUnknown).toBe(true);

    const acceptedStream = new Duplex({
      read() {},
      write(c: Buffer, _e: string, cb: () => void) { this.push(c); cb(); },
    });
    (acceptedStream as Duplex & { close?: () => void }).close = () => acceptedStream.destroy();
    let acceptedKnown = false;
    let rejectedKnown = false;
    client.emitEvent(
      'tcp connection',
      { destPort: 23457 },
      () => { acceptedKnown = true; return acceptedStream; },
      () => { rejectedKnown = true; },
    );
    expect(acceptedKnown).toBe(true);
    expect(rejectedKnown).toBe(false);
    acceptedStream.destroy();

    await manager.close('f-remote-1');
    expect(client.unforwardInCalls[0]).toEqual(['127.0.0.1', 23457]);
  });
});
