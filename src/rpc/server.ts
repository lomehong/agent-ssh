/**
 * Host 侧 RPC 服务端（T-14.5 垂直切片：最小装配）。
 *
 * 职责：帧循环（FrameReader）→ 信封校验 → 凭据解析与矩阵执行（authorize）
 * → 内建 hello/ping + 可注入 handlers → JsonRpcResponse。
 * 请求级无状态认证：信封可选 `auth` 成员携带凭据令牌（IM 单次令牌天然按请求）。
 * 审计：FORBIDDEN/未认证/帧超限 → auditLog（内存）+ 可选外部 sink（T-15 接真实存储）。
 * 超限即断连（§3.1）；hello 版本不匹配显式拒绝并附双方版本（§3.6）。
 */
import { createServer, type AddressInfo, type Server, type Socket } from 'net';
import { createServer as createTlsServer, type TlsOptions } from 'tls';
import { authorize, type RpcTables } from './authorize.js';
import { encodeFrame, FrameReader } from './frame.js';
import type { CallerClass } from './matrix.js';
import { PushHub } from './push.js';
import { RPC_ERROR, RPC_PROTOCOL_VERSION, negotiateHello } from './protocol.js';
import { buildToolManifest } from './manifest.js';
import { tracer } from '../observability/tracer.js';

export interface RpcServerAuditEvent {
  kind: 'forbidden' | 'unauthorized' | 'frame-oversize';
  connId: string;
  method?: string;
  detail?: string;
}

export interface RpcHandlerContext {
  callerClass: CallerClass;
  connId: string;
  /** 信封 auth 成员原文（会话令牌 renew 等自凭据方法需要）。 */
  presentedToken?: string;
}

export type RpcHandler = (params: unknown, ctx: RpcHandlerContext) => unknown | Promise<unknown>;

export interface RpcHostServerOpts {
  tables: RpcTables;
  /** 已知方法的处理器；host.hello/host.ping 内建（可覆盖）。缺失的已知方法按 -32601 应答。 */
  handlers?: Record<string, RpcHandler>;
  /** 外部审计 sink（T-15 接真实存储）；auditLog 始终内存留痕。 */
  audit?: (event: RpcServerAuditEvent) => void;
  /** hello 回显的证书指纹（§3.1 带外核对；TLS 装配在 T-15/T-17.5 接线）。 */
  certFingerprint?: string;
  protocolVersion?: string;
}

interface Conn {
  id: string;
  socket: Socket;
  reader: FrameReader;
  /** 该连接当前的 hub 退订函数（重复订阅时替换）。 */
  unsubscribe?: () => void;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function requestIdOf(v: unknown): string | number | null {
  return typeof v === 'string' || typeof v === 'number' ? v : null;
}

export class RpcHostServer {
  private readonly opts: RpcHostServerOpts;
  private readonly conns = new Map<string, Conn>();
  private readonly _hub = new PushHub();
  private server?: Server;
  private connSeq = 0;

  /** 内存审计留痕（测试/诊断用；生产审计走外部 sink）。 */
  readonly auditLog: RpcServerAuditEvent[] = [];

  constructor(opts: RpcHostServerOpts) {
    this.opts = opts;
  }

  get hub(): PushHub {
    return this._hub;
  }

  get connectionCount(): number {
    return this.conns.size;
  }

  /** 监听；默认环回明文。port 缺省 0（OS 分配，返回实际端口）。 */
  async listen(opts: { port?: number; host?: string; tls?: TlsOptions } = {}): Promise<number> {
    const host = opts.host ?? '127.0.0.1';
    const server: Server = opts.tls
      ? createTlsServer(opts.tls, (socket) => this.onConnection(socket))
      : createServer((socket) => this.onConnection(socket));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(opts.port ?? 0, host, () => resolve());
    });
    this.server = server;
    return (server.address() as AddressInfo).port;
  }

  async close(): Promise<void> {
    this.destroyAllConnections();
    const server = this.server;
    if (server === undefined) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    this.server = undefined;
  }

  /** 测试/运维用：掐断全部现存连接（客户端应按退避重连）。 */
  destroyAllConnections(): void {
    for (const conn of this.conns.values()) conn.socket.destroy();
  }

  private onConnection(socket: Socket): void {
    const conn: Conn = {
      id: `conn-${++this.connSeq}`,
      socket,
      reader: new FrameReader(),
    };
    this.conns.set(conn.id, conn);
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => this.onData(conn, chunk));
    socket.on('error', () => {});
    socket.on('close', () => {
      this.conns.delete(conn.id);
      this._hub.dropAll(conn.id);
    });
  }

  private onData(conn: Conn, chunk: string): void {
    const events = conn.reader.push(chunk);
    for (const event of events) {
      if (conn.reader.isDead() && !this.conns.has(conn.id)) return;
      switch (event.kind) {
        case 'frame':
          this.handleFrame(conn, event.value);
          break;
        case 'parseError':
          this.respondError(conn, null, -32700, 'Parse error: frame is not valid JSON');
          break;
        case 'oversize':
          this.audit({ kind: 'frame-oversize', connId: conn.id, detail: `${event.bytes} bytes` });
          conn.socket.destroy();
          return;
      }
    }
  }

  private handleFrame(conn: Conn, value: unknown): void {
    if (
      !isRecord(value) ||
      value.jsonrpc !== '2.0' ||
      typeof value.method !== 'string' ||
      requestIdOf(value.id) === null
    ) {
      // 本协议从简：一律应答（含 id:null），客户端语义无歧义
      this.respondError(
        conn,
        requestIdOf(isRecord(value) ? value.id : undefined),
        -32600,
        'Invalid Request: {jsonrpc:"2.0", id, method} envelope required',
      );
      return;
    }
    const req = value as { jsonrpc: '2.0'; id: string | number; method: string; params?: unknown; auth?: unknown };
    const token = typeof req.auth === 'string' ? req.auth : undefined;
    const auth = authorize(req.method, token, this.opts.tables);
    // rpc.request span（T-15 验收 3）：调度决策时刻——方法/调用类别/结果码。
    // handler 执行时长由既有 tool 级面覆盖； denied 调用的类别按真实凭据判。
    const span = tracer.startSpan('rpc.request');
    span.setAttribute('rpc.method', req.method);
    span.setAttribute('rpc.callerClass', auth.ok ? auth.callerClass : 'denied');
    span.setAttribute('rpc.code', auth.ok ? 'ok' : String(auth.code));
    span.end();
    if (!auth.ok) {
      if (auth.audit) {
        this.audit({
          kind: auth.code === RPC_ERROR.FORBIDDEN ? 'forbidden' : 'unauthorized',
          connId: conn.id,
          method: req.method,
          detail: auth.message,
        });
      }
      this.respondError(conn, req.id, auth.code, auth.message);
      return;
    }
    if (req.method === 'host.hello') {
      this.handleHello(conn, req);
      return;
    }
    if (req.method === 'host.ping') {
      this.respond(conn, req.id, { result: { pong: true } });
      return;
    }
    if (req.method === 'host.toolManifest') {
      // D3：单连接内 manifest 不可变——构建器为纯函数，装配在启动时缓存的结果
      // 等价于每次构建同一输出（manifest.test 确定性用例钉死）。
      this.respond(conn, req.id, {
        result: buildToolManifest(this.opts.protocolVersion ?? RPC_PROTOCOL_VERSION),
      });
      return;
    }
    if (req.method === 'approval.subscribe') {
      // 内建：把该连接的推送桥接到 hub（pending/settled 通知帧，无 id）
      conn.unsubscribe?.();
      conn.unsubscribe = this._hub.subscribe(conn.id, (event) => {
        if (conn.socket.destroyed) return;
        conn.socket.write(encodeFrame({ jsonrpc: '2.0', method: event.channel, params: event.payload }));
      });
      this.respond(conn, req.id, { result: { subscribed: true } });
      return;
    }
    const handler = this.opts.handlers?.[req.method];
    if (handler === undefined) {
      this.respondError(conn, req.id, RPC_ERROR.METHOD_NOT_FOUND, `Method ${req.method} is not implemented on this host`);
      return;
    }
    Promise.resolve(handler(req.params, { callerClass: auth.callerClass, connId: conn.id, presentedToken: token }))
      .then((result) => this.respond(conn, req.id, { result }))
      .catch((err: unknown) =>
        this.respondError(conn, req.id, RPC_ERROR.INTERNAL, err instanceof Error ? err.message : String(err)),
      );
  }

  private handleHello(
    conn: Conn,
    req: { id: string | number; params?: unknown },
  ): void {
    const params = isRecord(req.params) ? req.params : {};
    const clientVersion = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const version = this.opts.protocolVersion ?? RPC_PROTOCOL_VERSION;
    const neg = negotiateHello(clientVersion, version);
    if (!neg.ok) {
      this.respondError(
        conn,
        req.id,
        RPC_ERROR.VERSION_MISMATCH,
        `Protocol version mismatch: client ${neg.clientVersion}, host ${neg.serverVersion}`,
      );
      return;
    }
    const result: Record<string, unknown> = { protocolVersion: version };
    if (this.opts.certFingerprint !== undefined) result.certFingerprint = this.opts.certFingerprint;
    this.respond(conn, req.id, { result });
  }

  private respond(conn: Conn, id: string | number | null, body: { result?: unknown; error?: unknown }): void {
    if (conn.socket.destroyed) return;
    conn.socket.write(encodeFrame({ jsonrpc: '2.0', id, ...body }));
  }

  private respondError(conn: Conn, id: string | number | null, code: number, message: string): void {
    this.respond(conn, id, { error: { code, message } });
  }

  private audit(event: RpcServerAuditEvent): void {
    this.auditLog.push(event);
    this.opts.audit?.(event);
  }
}
