/**
 * stub/审批端侧 RPC 客户端（T-14.5 垂直切片）。
 *
 * 连接纪律先行（§3.1/A7/K8-①）：assertClientConnectAllowed + TLS 时 pin 常时校验
 * （fingerprint256 对 AGENT_SSH_HOST_PIN，不匹配即拒）。connect 即 hello（版本协商，
 * 失败显式抛出并附双方版本）。请求 id 单调关联 + 超时；断线（非本端 close）按
 * 指数退避自动重连，成功后重置退避并重放 approval.subscribe（§3.5：重连后补偿）。
 * close 后不重连，未连接时调用 fail-fast（绝不本地降级）。
 */
import { connect as netConnect, type Socket } from 'net';
import { connect as tlsConnect, type TLSSocket } from 'tls';
import { encodeFrame, FrameReader } from './frame.js';
import type { PushEvent } from './push.js';
import { RPC_PROTOCOL_VERSION, type JsonRpcResponse } from './protocol.js';
import { nextRetryDelayMs } from './reconnect.js';
import { assertClientConnectAllowed, verifyPin } from './transport-security.js';

export interface RpcClientOpts {
  host: string;
  port: number;
  /** 凭据令牌（agent 静态 / operator 会话 / IM 单次），随请求信封 auth 成员。 */
  token: string;
  /** 缺省 RPC_PROTOCOL_VERSION。 */
  protocolVersion?: string;
  /** 设置即走 TLS；pin 必填（fail-closed）。 */
  tls?: { pin: string };
  requestTimeoutMs?: number;
  connectTimeoutMs?: number;
  /** 断线自动重连，缺省开。 */
  reconnect?: boolean;
  /**
   * operator 引导模式：跳过 connect 时的 hello（hello 需有效凭据，而无凭据面
   * 靠 auth.session.start 换会话——先 start 再以会话令牌重连走正常 hello）。
   * 缺省 false（agent/会话客户端都应 hello）。
   */
  skipHello?: boolean;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error & { code?: number }) => void;
  timer: NodeJS.Timeout;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;

export class RpcClient {
  private readonly opts: RpcClientOpts;
  private socket?: Socket;
  private reader = new FrameReader();
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private approvalCallback?: (payload: unknown) => void;
  private attempt = 0;
  private stopping = false;
  private reconnectTimer?: NodeJS.Timeout;
  private ready = false;

  constructor(opts: RpcClientOpts) {
    this.opts = opts;
  }

  isConnected(): boolean {
    return this.ready;
  }

  async connect(): Promise<void> {
    this.stopping = false;
    const tlsOn = this.opts.tls !== undefined;
    assertClientConnectAllowed({ host: this.opts.host, tls: tlsOn, pin: this.opts.tls?.pin });
    const socket = await this.dial(tlsOn);
    this.reader = new FrameReader();
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      // 重连竞态防护：陈旧连接的迟到事件不得污染新连接状态
      if (this.socket !== socket) return;
      this.onData(chunk);
    });
    socket.on('error', () => {});
    socket.on('close', () => this.onClose(socket));
    if (this.opts.skipHello !== true) {
      await this.rawCall('host.hello', { protocolVersion: this.opts.protocolVersion ?? RPC_PROTOCOL_VERSION });
    }
    this.ready = true;
    this.attempt = 0;
    // 重连成功后重放订阅（§3.5：重连后 approval.list 补偿属 T-16 语义，订阅重放在此）
    if (this.approvalCallback !== undefined) {
      await this.rawCall('approval.subscribe');
    }
  }

  /** 未连接（含 close 后）直接抛错——fail-fast，绝不排队等待重连。 */
  async call<T = unknown>(method: string, params?: unknown): Promise<T> {
    if (!this.ready || this.socket === undefined) {
      throw new Error(`RPC client is not connected: ${method}`);
    }
    return (await this.rawCall(method, params)) as T;
  }

  /** 订阅审批推送（operator 通道）。重连后自动重放。 */
  async subscribeApproval(callback: (payload: unknown) => void): Promise<void> {
    this.approvalCallback = callback;
    await this.rawCall('approval.subscribe');
  }

  async close(): Promise<void> {
    this.stopping = true;
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.ready = false;
    this.failAllPending(new Error('RPC client closed'));
    this.socket?.destroy();
    this.socket = undefined;
  }

  private dial(useTls: boolean): Promise<Socket> {
    const timeoutMs = this.opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const socket = useTls
        ? tlsConnect({ host: this.opts.host, port: this.opts.port, rejectUnauthorized: false })
        : netConnect({ host: this.opts.host, port: this.opts.port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`Connect timeout after ${timeoutMs}ms: ${this.opts.host}:${this.opts.port}`));
      }, timeoutMs);
      socket.once('error', (err: Error) => {
        clearTimeout(timer);
        reject(err);
      });
      const readyEvent = useTls ? 'secureConnect' : 'connect';
      socket.once(readyEvent, () => {
        clearTimeout(timer);
        if (useTls) {
          // pin 一票否决（A7）：指纹不匹配即断
          const fingerprint = (socket as TLSSocket).getPeerCertificate().fingerprint256 ?? '';
          try {
            verifyPin(fingerprint, this.opts.tls!.pin);
          } catch (err) {
            socket.destroy();
            reject(err as Error);
            return;
          }
        }
        resolve(socket);
      });
    });
  }

  private rawCall(method: string, params?: unknown): Promise<unknown> {
    const socket = this.socket;
    if (socket === undefined || socket.destroyed) {
      return Promise.reject(new Error(`RPC connection is not open: ${method}`));
    }
    const id = this.nextId++;
    const envelope: Record<string, unknown> = { jsonrpc: '2.0', id, method };
    if (params !== undefined) envelope.params = params;
    if (this.opts.token !== '') envelope.auth = this.opts.token;
    const timeoutMs = this.opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`RPC request timeout after ${timeoutMs}ms: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      socket.write(encodeFrame(envelope));
    });
  }

  private onData(chunk: string): void {
    const events = this.reader.push(chunk);
    for (const event of events) {
      if (event.kind === 'frame') this.handleMessage(event.value);
      // parseError/oversize 来自对端：服务端不会发；出现即视为线路不可信
      if (event.kind === 'oversize') this.socket?.destroy();
    }
  }

  private handleMessage(value: unknown): void {
    const msg = value as Partial<JsonRpcResponse> & { method?: string; params?: unknown };
    if (typeof msg.method === 'string' && msg.id === undefined) {
      // 通知：approval 推送
      if ((msg.method === 'approval.pending' || msg.method === 'approval.settled') && this.approvalCallback) {
        const payload: PushEvent = { channel: msg.method, payload: msg.params };
        this.approvalCallback(payload.payload);
      }
      return;
    }
    if (msg.id === undefined) return;
    const pending = this.pending.get(msg.id as number);
    if (pending === undefined) return;
    this.pending.delete(msg.id as number);
    clearTimeout(pending.timer);
    if (msg.error !== undefined) {
      const err = msg.error as { code: number; message: string };
      const failure = new Error(err.message) as Error & { code?: number };
      failure.code = err.code;
      pending.reject(failure);
    } else {
      pending.resolve(msg.result);
    }
  }

  private onClose(socket: Socket): void {
    // 仅当关闭的是「当前」连接才走重连；陈旧连接的迟到 close 直接忽略
    if (this.socket !== socket) return;
    const wasReady = this.ready;
    this.ready = false;
    this.failAllPending(new Error('RPC connection closed'));
    this.socket = undefined;
    if (this.stopping || this.opts.reconnect === false || !wasReady) return;
    this.scheduleReconnect();
  }

  /**
   * 退避重连调度（唯一入口）：connect() 的失败在此 catch 内续期，保证拒绝
   * 永远有人接——Host 持续不可达时绝不产生 unhandled rejection（Node≥15 默认
   * 因此崩进程，评审 T-14.5 标准轴硬伤 #1）。timer 在册时不重复调度。
   */
  private scheduleReconnect(): void {
    if (this.stopping || this.opts.reconnect === false || this.reconnectTimer !== undefined) return;
    const delay = nextRetryDelayMs(this.attempt);
    this.attempt++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect().catch(() => this.scheduleReconnect());
    }, delay);
  }

  private failAllPending(err: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pending.clear();
  }
}
