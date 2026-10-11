import { createServer, connect as netConnect, type Server, type Socket } from 'node:net';
import type { Client, ClientChannel } from 'ssh2';
import type { Profile } from '../types.js';

/**
 * Port-forwarding manager (agent-ssh T-06): local (-L), remote (-R) and dynamic
 * (-D, SOCKS5 CONNECT) tunnels over one SSH connection, with explicit lifecycle.
 *
 * Authorization model (layered, matching the plan):
 * - `forward:open` classifies destructive (classifier synthetic floor), so the
 *   role×tier matrix and the approval gate apply to every tunnel — a `viewer`
 *   holds no destructive class anywhere, which IS "viewer 禁转发".
 * - The denylist matches the synthesized command string, which embeds the full
 *   listen/target pair — an operator rule like `internal-db:5432` refuses the
 *   tunnel before it opens, the same way SFTP paths are denied.
 * - Dynamic forwarding is additionally gated by `allowDynamicForwarding`
 *   (default false): an open SOCKS listener is a generic egress path and stays
 *   opt-in even where destructive commands are approved.
 *
 * The SOCKS5 implementation below is CONNECT-only with no auth, hand-rolled
 * because the only npm option (mscdex/socksv5) is unmaintained and the protocol
 * subset a tunnel needs is ~60 lines — a supply-chain decision, recorded here.
 */

export type ForwardMode = 'local' | 'remote' | 'dynamic';

export interface ForwardInfo {
  id: string;
  mode: ForwardMode;
  /** What this machine listens on. */
  listen: string;
  /** Where the far end lands (absent until a dynamic tunnel's peer names one). */
  target?: string;
  activeConnections: number;
  closed: boolean;
}

export interface ForwardOpenRequest {
  listenHost?: string;
  listenPort: number;
  targetHost?: string;
  targetPort?: number;
}

export interface ForwardManagerOptions {
  profile: () => Profile;
  getClient: () => Client;
  allowDynamic: () => boolean;
}

interface ForwardEntry {
  id: string;
  mode: ForwardMode;
  listenHost: string;
  listenPort: number;
  targetHost?: string;
  targetPort?: number;
  server?: Server;
  closed: boolean;
  active: number;
  sockets: Set<Socket>;
}

/** Wire one local socket to one SSH channel, counting the pair on the entry. */
function pairSockets(entry: ForwardEntry, a: Socket, b: ClientChannel): void {
  entry.active++;
  entry.sockets.add(a);
  const done = () => {
    entry.active--;
    entry.sockets.delete(a);
  };
  a.on('close', done);
  b.on('close', done);
  a.pipe(b).pipe(a);
  const kill = () => {
    a.destroy();
    // ssh2 channels have close(); a bare Duplex (tests) has destroy.
    if (typeof (b as { close?: () => void }).close === 'function') (b as { close: () => void }).close();
    else b.destroy();
  };
  a.on('error', kill);
  b.on('error', kill);
}

export class ForwardManager {
  private entries = new Map<string, ForwardEntry>();
  private seq = 0;

  constructor(private readonly opts: ForwardManagerOptions) {}

  list(): ForwardInfo[] {
    return [...this.entries.values()].map((e) => ({
      id: e.id,
      mode: e.mode,
      listen: `${e.listenHost}:${e.listenPort}`,
      target: e.targetHost ? `${e.targetHost}:${e.targetPort}` : undefined,
      activeConnections: e.active,
      closed: e.closed,
    }));
  }

  get size(): number {
    return this.entries.size;
  }

  async openLocal(request: ForwardOpenRequest & { targetHost: string; targetPort: number }): Promise<ForwardInfo> {
    const listenHost = request.listenHost ?? '127.0.0.1';
    const entry = this.newEntry('local', listenHost, request.listenPort, request.targetHost, request.targetPort);
    const client = this.client();
    const server = createServer((socket) => {
      if (entry.closed) return socket.destroy();
      client.forwardOut(socket.remoteAddress ?? listenHost, socket.remotePort ?? 0, request.targetHost, request.targetPort, (err, stream) => {
        if (err || !stream) return socket.destroy();
        pairSockets(entry, socket, stream);
      });
    });
    return this.listen(entry, server);
  }

  async openRemote(request: ForwardOpenRequest & { targetHost: string; targetPort: number }): Promise<ForwardInfo> {
    const bindHost = request.listenHost ?? '127.0.0.1';
    const entry = this.newEntry('remote', bindHost, request.listenPort, request.targetHost, request.targetPort);
    const client = this.client();
    // One 'tcp connection' listener per client dispatches by bound port; the
    // manager registers it lazily and keeps it for the life of the client —
    // ssh2 gives no per-request correlation beyond the destination port.
    client.on('tcp connection', (info, accept, reject) => {
      const target = [...this.entries.values()].find(
        (e) => e.mode === 'remote' && !e.closed && e.listenPort === info.destPort,
      );
      if (!target?.targetPort || !target.targetHost) return reject();
      const stream = accept();
      const local = netConnect(target.targetPort, target.targetHost, () => {
        pairSockets(target, local, stream);
      });
      local.on('error', () => {
        try { stream.close(); } catch { /* peer gone */ }
      });
    });
    const boundPort: number = await new Promise((resolve, reject) => {
      client.forwardIn(bindHost, request.listenPort, (err?: Error, port?: number) => (err ? reject(err) : resolve(port ?? request.listenPort)));
    });
    entry.listenPort = boundPort;
    return this.finalize(entry);
  }

  async openDynamic(request: ForwardOpenRequest): Promise<ForwardInfo> {
    if (!this.opts.allowDynamic()) {
      throw new Error(
        'Dynamic (SOCKS) forwarding is disabled. It is a generic egress path, so it is ' +
        'off by default: set allowDynamicForwarding = true in [defaults] to enable it.',
      );
    }
    const listenHost = request.listenHost ?? '127.0.0.1';
    const entry = this.newEntry('dynamic', listenHost, request.listenPort);
    const client = this.client();
    const server = createServer((socket) => {
      if (entry.closed) return socket.destroy();
      socksConnect(socket, (dstHost, dstPort) => {
        client.forwardOut(socket.remoteAddress ?? listenHost, socket.remotePort ?? 0, dstHost, dstPort, (err, stream) => {
          if (err || !stream) return socket.destroy();
          pairSockets(entry, socket, stream);
        });
      });
    });
    return this.listen(entry, server);
  }

  async close(id: string): Promise<{ outcome: 'closed' | 'not-found'; mode?: ForwardMode }> {
    const entry = this.entries.get(id);
    if (!entry) return { outcome: 'not-found' };
    entry.closed = true;
    if (entry.mode === 'remote') {
      // Best effort: the server may refuse the cancel (or never answer); the
      // local bookkeeping is authoritative for this manager either way.
      await new Promise<void>((resolve) => {
        try {
          this.opts.getClient().unforwardIn(entry.listenHost, entry.listenPort, () => resolve());
        } catch { resolve(); }
      });
    }
    entry.server?.close();
    for (const socket of entry.sockets) socket.destroy();
    this.entries.delete(id);
    return { outcome: 'closed', mode: entry.mode };
  }

  async closeAll(): Promise<void> {
    for (const id of [...this.entries.keys()]) await this.close(id);
  }

  private client(): Client {
    return this.opts.getClient();
  }

  private newEntry(mode: ForwardMode, listenHost: string, listenPort: number, targetHost?: string, targetPort?: number): ForwardEntry {
    this.seq++;
    const entry: ForwardEntry = {
      id: `f-${mode}-${this.seq}`,
      mode,
      listenHost,
      listenPort,
      targetHost,
      targetPort,
      closed: false,
      active: 0,
      sockets: new Set(),
    };
    this.entries.set(entry.id, entry);
    return entry;
  }

  private listen(entry: ForwardEntry, server: Server): Promise<ForwardInfo> {
    entry.server = server;
    return new Promise((resolve, reject) => {
      server.once('error', (err) => {
        this.entries.delete(entry.id);
        reject(err);
      });
      server.listen(entry.listenPort, entry.listenHost, () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') entry.listenPort = addr.port;
        resolve(this.finalize(entry));
      });
    });
  }

  private finalize(entry: ForwardEntry): ForwardInfo {
    return this.list().find((f) => f.id === entry.id)!;
  }
}

/**
 * Minimal SOCKS5 server handshake on one client socket: method negotiation
 * (no-auth only), then CONNECT. Everything else — BIND, UDP, auth methods —
 * replies with the standard error code and drops, because a forwarding tool
 * that needs BIND should say so in a design, not in a protocol corner.
 */
function socksConnect(socket: Socket, onConnect: (host: string, port: number) => void): void {
  let stage: 'greet' | 'request' = 'greet';
  socket.on('error', () => socket.destroy());
  socket.on('data', (buf: Buffer) => {
    if (stage === 'greet') {
      if (buf.length < 2 || buf[0] !== 0x05) return socket.destroy();
      const methods = buf.subarray(2, 2 + buf[1]);
      if (!methods.includes(0x00)) {
        socket.end(Buffer.from([0x05, 0xff]));
        return;
      }
      socket.write(Buffer.from([0x05, 0x00]));
      stage = 'request';
      return;
    }
    // Request: VER CMD RSV ATYP ADDR.PORT
    if (buf.length < 7 || buf[0] !== 0x05 || buf[1] !== 0x01) {
      socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      return;
    }
    const atyp = buf[3];
    let host = '';
    let portOffset = 0;
    if (atyp === 0x01 && buf.length >= 10) {
      host = [...buf.subarray(4, 8)].join('.');
      portOffset = 8;
    } else if (atyp === 0x03 && buf.length >= 5 + buf[4] + 2) {
      host = buf.subarray(5, 5 + buf[4]).toString('ascii');
      portOffset = 5 + buf[4];
    } else if (atyp === 0x04 && buf.length >= 22) {
      host = [...buf.subarray(4, 20)].map((b) => b.toString(16)).join(':');
      portOffset = 20;
    } else {
      socket.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      return;
    }
    const port = buf.readUInt16BE(portOffset);
    socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
    socket.removeAllListeners('data');
    onConnect(host, port);
  });
}
