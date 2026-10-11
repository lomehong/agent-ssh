import { createServer, connect as netConnect, type Server, type Socket } from 'node:net';
import type { Client, ClientChannel } from 'ssh2';
import type { Profile } from '../types.js';

/**
 * 端口转发管理器（agent-ssh T-06）：一条 SSH 连接上的 local（-L）、
 * remote（-R）与 dynamic（-D，SOCKS5 CONNECT）隧道，生命周期显式。
 *
 * 授权模型（分层，与计划一致）：
 * - `forward:open` 归类为 destructive（分类器合成下限），因此
 *   角色×层级矩阵与审批门作用于每条隧道——`viewer` 在任何层级
 *   都不持有 destructive 类别，这正是「viewer 禁转发」。
 * - denylist 匹配合成命令字符串，其中嵌有完整的
 *   监听/目标对——`internal-db:5432` 这样的运维规则能在隧道
 *   建立前拒绝它，与 SFTP 路径被拒同路。
 * - dynamic 转发额外受 `allowDynamicForwarding` 把门
 *   （默认 false）：开放的 SOCKS 监听是不分目标的出网通道，
 *   即使破坏性命令可被批准，它也保持 opt-in。
 *
 * 下面的 SOCKS5 实现仅 CONNECT、无认证、手写，
 * 原因是 npm 上唯一选项（mscdex/socksv5）无人维护，而隧道需要的
 * 协议子集约 60 行——一条供应链决定，在此登记。
 */

export type ForwardMode = 'local' | 'remote' | 'dynamic';

export interface ForwardInfo {
  id: string;
  mode: ForwardMode;
  /** 本机监听什么。 */
  listen: string;
  /** 远端落到哪（dynamic 隧道的对端点名之前为空）。 */
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

/** 把一个本地套接字接到一条 SSH 通道，并在条目上为这对计数。 */
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
    // ssh2 通道有 close()；裸 Duplex（测试）有 destroy。
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
    // 每客户端一个 'tcp connection' 监听器，按绑定端口分发；
    // 管理器惰性注册它并在客户端存续期保留——
    // 除目的端口外 ssh2 不提供逐请求的关联。
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
      // 尽力而为：服务器可能拒绝取消（或永不回答）；
      // 无论哪种，本地簿记对本管理器都是权威。
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
  * 单个客户端套接字上的最小 SOCKS5 服务器握手：方法协商
  * （仅 no-auth），然后 CONNECT。其余一切——BIND、UDP、其他认证方式——
  * 以标准错误码应答后断开：需要 BIND 的转发工具
  * 应该在设计文档里说，而不是藏在协议角落。
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
