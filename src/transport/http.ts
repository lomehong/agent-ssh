import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import { SERVER_VERSION } from '../version.js';
import { OperatorError } from '../errors.js';

import {
  AuthFailureLimiter,
  ClientRateLimiter,
  DEFAULT_AUTH_FAILURE_LIMIT,
} from '../rpc/limiters.js';
import { clientKey } from '../rpc/address.js';
import { HTTP_BODY_LIMIT_BYTES as MAX_BODY_SIZE, SizeCappedText } from '../rpc/bounded-input.js';

// T-13.5 预重构：限流器/地址键控/有界输入三件已物理迁入 src/rpc/（原样迁移，零行为变化）。
// 下方 re-export 保持 http.js 既有导入面（test/unit/transport/http.test.ts 依赖）；
// T-15 删除 http.ts 时，导入方改指 rpc/ 模块。
export {
  AuthFailureLimiter,
  ClientRateLimiter,
  DEFAULT_AUTH_FAILURE_LIMIT,
  MAX_TRACKED_CLIENTS,
} from '../rpc/limiters.js';
export { clientKey } from '../rpc/address.js';
/** Cap on concurrent MCP sessions, so unauthenticated-adjacent churn can't grow the map without bound. */
const MAX_SESSIONS = 64;
/**
 * MCP 会话在被回收前可多长时间不收到请求。清理是惰性的，
 * 空闲服务器零成本，也没有需要清理的间隔。
 */
export const DEFAULT_SESSION_IDLE_TTL_MS = 30 * 60_000;

export interface HttpTransportOpts {
  port: number;
  host?: string;
  bearerToken?: string;
  registry: ConnectionRegistry;
  /** MCP session idle timeout. Defaults to `DEFAULT_SESSION_IDLE_TTL_MS`. */
  sessionIdleTtlMs?: number;
  /**
    * 每客户端每分钟已认证请求上限，GET /health 以外的所有路由。
    * 0 或未设置禁用限制。客户端键控方式同 authFailureLimit。
    *
   */
  rateLimit?: number;
  /**
    * 每客户端每分钟允许的认证失败次数。默认
    * DEFAULT_AUTH_FAILURE_LIMIT；0 禁用检查。正确令牌永不从此预算消耗，
    * 正常客户端不会限流自己；与失败者共享地址的客户端确实要等，
    * 这正是该限制的用途。
   */
  authFailureLimit?: number;
  /**
    * 是否从 X-Forwarded-For 读取客户端地址。默认关，因为
    * 能设置该头部的客户端可以自选限流键。
   */
  trustProxy?: boolean;
  /**
    * 允许经 X-Forwarded-For 代表其他客户端的对端地址。空即仅回环，
    * 即 README 所述部署。
   */
  trustedProxies?: string[];
  /**
    * DNS 重绑定防护接受的 Host 头。默认为绑定地址和 localhost；
    * 在呈现不同主机名的反向代理后运行时设置。
    *
   */
  allowedHosts?: string[];
}

function jsonRpcError(res: ServerResponse, status: number, code: number, message: string): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}

/**
 * @param createMcpServer 每个 MCP 会话构建新的 McpServer。McpServer
 *   绑定恰好一个传输，共享实例只会让第一个客户端初始化——
 *   该客户端离开后保持不可用。
 */
export async function startHttpServer(
  createMcpServer: () => McpServer | Promise<McpServer>,
  opts: HttpTransportOpts,
): Promise<Server> {
  const { port, host = '127.0.0.1', bearerToken, registry } = opts;

  if (!bearerToken) {
    throw new OperatorError(
      'HTTP transport requires --bearerToken. Example: --transport=http --bearerToken=secret\n' +
      'Without authentication, any network client can execute SSH commands on your hosts.',
    );
  }

  const authFailureLimit = opts.authFailureLimit ?? DEFAULT_AUTH_FAILURE_LIMIT;
  const authFailureLimiter = authFailureLimit > 0
    ? new AuthFailureLimiter(authFailureLimit)
    : null;

  // 只说一次，在确实要紧时。--trustProxy 关闭时代理后部署中每个
  // 客户端都键控在代理的套接字地址上，共享一份失败预算和一份
  // 请求预算——任何人十次失败锁死所有人，一个忙碌客户端
  // 饿死其余。README 让运维在代理终结 TLS，所以这是它推荐的
  // 配置，折叠在合法客户端被拒前不可见。
  //
  let warnedSharedBudget = false;
  const warnSharedBudget = () => {
    if (warnedSharedBudget) return;
    warnedSharedBudget = true;
    console.error(
      'POLICY WARNING: X-Forwarded-For is present but not being used to tell clients ' +
      'apart, so every client is charged to one key: one failed-auth budget and one ' +
      'request budget between them, for whichever of the two is on, and one client can ' +
      'lock out or starve the rest. Either --trustProxy is off, or the peer is not a ' +
      'trusted proxy (bare --trustProxy trusts a loopback peer; name others with ' +
      '--trustedProxies), or the rightmost entry is not an address this server can read.',
    );
  };

  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new ClientRateLimiter(opts.rateLimit)
    : null;

  // DNS 重绑定：用户访问的页面可以让其浏览器 POST 到 localhost 服务器，
  // bearer 令牌在浏览器被诱导附上时也帮不了忙。
  // 验证 Host 头正是阻止它的方式。
  // GHSA-w48q-cv73-mx4w 正是这个问题，SDK 留给调用方。
  const allowedHosts = opts.allowedHosts?.length
    ? opts.allowedHosts
    : [`${host}:${port}`, `localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`];

  interface Session {
    id?: string;
    transport: StreamableHTTPServerTransport;
    server: McpServer;
    lastActivity: number;
    finiteInFlight: number;
    openSseStreams: number;
    closing: boolean;
    pending: boolean;
    releasePending: () => void;
    /** Drops the eviction this session's own initialize claimed, if it has not been admitted. */
    releaseEvictionClaim: () => void;
    closePromise?: Promise<void>;
  }

  interface PendingSessionReservation {
    createdAt: number;
    released: boolean;
  }

  interface McpSessionStats {
    cap: number;
    total: number;
    pending: number;
    finiteInFlightSessions: number;
    finiteInFlightRequests: number;
    openSseStreams: number;
    evictable: number;
    oldestActivityMs: number;
    oldestPendingMs: number;
  }

  type SessionCloseReason = 'delete' | 'ttl' | 'lru' | 'init-abort' | 'transport-close';

  const sessionIdleTtlMs = opts.sessionIdleTtlMs && opts.sessionIdleTtlMs > 0
    ? opts.sessionIdleTtlMs
    : DEFAULT_SESSION_IDLE_TTL_MS;
  const sessions = new Map<string, Session>();
  const pendingReservations = new Set<PendingSessionReservation>();
  /**
    * 在上限处为尚未接纳的 initialize 留出的逐出候选，
    * 并发的各自依赖不同会话，全无剩余时 503。声明不逐出任何人：
    * 空间只在 initialize 被接纳时腾出，SDK 后来拒绝的
    *（坏 Host、错 Accept）或客户端断开的
    * 不会让其他客户端失去会话。
   */
  const evictionClaims = new Set<Session>();

  function reservePendingSession(): () => void {
    const reservation = { createdAt: Date.now(), released: false };
    pendingReservations.add(reservation);
    return () => {
      if (reservation.released) return;
      reservation.released = true;
      pendingReservations.delete(reservation);
    };
  }

  function sessionStats(now = Date.now()): McpSessionStats {
    let finiteInFlightSessions = 0;
    let finiteInFlightRequests = 0;
    let openSseStreams = 0;
    let evictable = 0;
    let oldestActivity = now;
    let oldestPending = now;

    for (const session of sessions.values()) {
      if (session.finiteInFlight > 0) finiteInFlightSessions++;
      else if (!evictionClaims.has(session)) evictable++;
      finiteInFlightRequests += session.finiteInFlight;
      openSseStreams += session.openSseStreams;
      oldestActivity = Math.min(oldestActivity, session.lastActivity);
    }
    for (const reservation of pendingReservations) {
      oldestPending = Math.min(oldestPending, reservation.createdAt);
    }

    return {
      cap: MAX_SESSIONS,
      total: sessions.size,
      pending: pendingReservations.size,
      finiteInFlightSessions,
      finiteInFlightRequests,
      openSseStreams,
      evictable,
      oldestActivityMs: sessions.size > 0 ? Math.max(0, now - oldestActivity) : 0,
      oldestPendingMs: pendingReservations.size > 0 ? Math.max(0, now - oldestPending) : 0,
    };
  }

  function formatSessionStats(stats: McpSessionStats): string {
    return Object.entries(stats).map(([key, value]) => `${key}=${value}`).join(' ');
  }

  function detachSession(session: Session, reason: SessionCloseReason): void {
    if (session.closing) return;
    session.closing = true;
    if (session.id && sessions.get(session.id) === session) sessions.delete(session.id);
    // 在其声明者被接纳之前因其他原因消失：槽位空闲。
    evictionClaims.delete(session);
    session.pending = false;
    session.releasePending();
    session.releaseEvictionClaim();
    console.error(`MCP session closed reason=${reason}`);
  }

  /** Close both owners so transport streams and resources attached to the McpServer are released. */
  function closeSession(session: Session, reason: SessionCloseReason): Promise<void> {
    if (!session.closePromise) {
      detachSession(session, reason);
      session.closePromise = (async () => {
        await session.transport.close().catch(() => {});
        await session.server.close().catch(() => {});
      })();
    }
    return session.closePromise;
  }

  /**
    * 空闲意味着客户端在此服务器上无任何打开的东西：无请求在途
    * 也无 SSE 流。持有的流是已连接 Streamable-HTTP 客户端等待通知的
    * 方式，它只在打开时标记活动，因此仅按 lastActivity 判断
    * 会让已过期但仍连接的客户端排在最前。
   */
  function isIdle(session: Session, now: number): boolean {
    return session.finiteInFlight === 0
      && session.openSseStreams === 0
      && now - session.lastActivity >= sessionIdleTtlMs;
  }

  function closeExpiredSessions(now: number): void {
    for (const session of sessions.values()) {
      if (isIdle(session, now)) void closeSession(session, 'ttl');
    }
  }

  /**
    * 上限时逐出的会话：绝不在途请求的，无打开流的先于持流的，
    * 各自内最老的在前。持流者作为最后手段仍可逐出，因为客户端
    * 未发 FIN/RST 就消失会保持流打开直到写入失败，
    * 可能需要很多分钟，64 个这样的会话在那之前拒绝每个新客户端。
    *
   */
  function pickEvictionCandidate(): Session | undefined {
    let best: Session | undefined;
    for (const session of sessions.values()) {
      if (session.finiteInFlight > 0 || evictionClaims.has(session)) continue;
      if (!best) { best = session; continue; }
      const holdsStream = session.openSseStreams > 0;
      const bestHoldsStream = best.openSseStreams > 0;
      if (holdsStream !== bestHoldsStream ? !holdsStream : session.lastActivity < best.lastActivity) {
        best = session;
      }
    }
    return best;
  }

  function beginRequest(session: Session, req: IncomingMessage, res: ServerResponse): () => void {
    const isSseStream = req.method === 'GET';
    if (isSseStream) session.openSseStreams++;
    else session.finiteInFlight++;
    session.lastActivity = Date.now();
    const initializing = session.pending;
    let completed = false;
    const complete = (aborted: boolean) => {
      if (completed) return;
      completed = true;
      res.off('finish', onFinish);
      res.off('close', onClose);
      if (isSseStream) session.openSseStreams--;
      else session.finiteInFlight--;
      session.lastActivity = Date.now();
      if (session.pending || (initializing && aborted)) void closeSession(session, 'init-abort');
    };
    const onFinish = () => { complete(false); };
    const onClose = () => { complete(!res.writableFinished); };
    res.once('finish', onFinish);
    res.once('close', onClose);
    return () => { complete(true); };
  }

  /** Route to the session's transport, or start a new session on `initialize`. */
  async function resolveTransport(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<Session | null> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    if (sessionId) {
      const existing = sessions.get(sessionId);
      if (existing) {
        if (isIdle(existing, Date.now())) {
          await closeSession(existing, 'ttl');
        } else {
          return existing;
        }
      }
      jsonRpcError(res, 404, -32001, 'Session not found or expired. Re-initialize to obtain a new session.');
      return null;
    }

    const body = Array.isArray(parsedBody) ? parsedBody : [parsedBody];
    if (!body.some((m) => isInitializeRequest(m))) {
      jsonRpcError(res, 400, -32000, 'Missing mcp-session-id header. Send an initialize request first.');
      return null;
    }

    closeExpiredSessions(Date.now());

    // 在上限处声明一个会话来腾空间；pickEvictionCandidate 跳过
    // 另一个 initialize 已声明的会话，并发的各自声明不同的，
    // 全无剩余时才 503。
    let claim: Session | undefined;
    if (sessions.size + pendingReservations.size >= MAX_SESSIONS) {
      claim = pickEvictionCandidate();
      if (!claim) {
        console.error(`MCP session limit reached ${formatSessionStats(sessionStats())}`);
        jsonRpcError(res, 503, -32000, `Server is at its session limit (${MAX_SESSIONS}). Close an existing session and retry.`);
        return null;
      }
      evictionClaims.add(claim);
    }
    const releaseClaim = () => {
      if (claim) evictionClaims.delete(claim);
      claim = undefined;
    };

    const releasePending = reservePendingSession();
    let clientClosed = false;
    const markClientClosed = () => {
      clientClosed = true;
      releasePending();
      releaseClaim();
    };
    res.once('close', markClientClosed);

    let mcp: McpServer | undefined;
    let session: Session | undefined;
    try {
      mcp = await createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableDnsRebindingProtection: true,
        allowedHosts,
        onsessioninitialized: (id) => {
          session!.id = id;
          if (session!.pending) {
            session!.pending = false;
            session!.releasePending();
          }
          releaseClaim();
          if (session!.closing) return;
          // 已接纳：现在腾空间，只数已接纳的会话，另一个仍在途的
          // initialize 可能还会被拒。声明只保留了候选；现在取的是
          // 最久不活跃的会话，可能已变成不同的一个。如果所有会话
          // 都忙则超出上限而非拒绝已接纳的客户端，下次接纳
          // 会把计数拉回上限之下。
          //
          while (sessions.size >= MAX_SESSIONS) {
            const victim = pickEvictionCandidate();
            if (!victim) break;
            void closeSession(victim, 'lru');
          }
          sessions.set(id, session!);
        },
        onsessionclosed: () => { detachSession(session!, 'delete'); },
      });
      session = {
        transport,
        server: mcp,
        lastActivity: Date.now(),
        finiteInFlight: 0,
        openSseStreams: 0,
        closing: false,
        pending: true,
        releasePending,
        releaseEvictionClaim: releaseClaim,
      };
      // 覆盖非 DELETE 的传输拆除（客户端断连、错误）。
      transport.onclose = () => {
        detachSession(session!, 'transport-close');
      };

      await mcp.connect(transport);
      if (clientClosed || res.destroyed) {
        await closeSession(session, 'init-abort');
        return null;
      }
      return session;
    } catch (error) {
      if (session) await closeSession(session, 'init-abort');
      else {
        releasePending();
        releaseClaim();
      }
      throw error;
    } finally {
      res.off('close', markClientClosed);
    }
  }

  async function handleMcpRequest(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<void> {
    const session = await resolveTransport(req, res, parsedBody);
    if (!session) return;
    if (res.destroyed) {
      if (session.pending) await closeSession(session, 'init-abort');
      return;
    }
    const finish = beginRequest(session, req, res);
    try {
      await session.transport.handleRequest(req, res, parsedBody);
    } catch (error) {
      finish();
      throw error;
    }
  }

  /**
    * 没有它拒绝未处理、客户端永远得不到回答。
    *
   */
  async function serveMcpRequest(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<void> {
    try {
      await handleMcpRequest(req, res, parsedBody);
    } catch (error) {
      console.error('MCP request failed:', error);
      if (!res.headersSent) jsonRpcError(res, 500, -32603, 'Internal error');
    }
  }

  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    // 存活探针惯例上不认证，README 列出 /health 无认证警告。它暴露
    // 「进程存活」和是否有 profile 被配置——见下方 handler 为何
    // 第二位不是秘密。
    const isHealthProbe = req.method === 'GET' && url.pathname === '/health';

    if (!isHealthProbe) {
      let key = '';
      if (authFailureLimiter || rateLimiter) {
        const resolved = clientKey(req, opts.trustProxy === true, opts.trustedProxies);
        key = resolved.key;
        // 两个方向都告警。无 --trustProxy 时代理后部署共享
        // 一份预算；*有*它时无法读取的条目使同样的折叠保持，
        // 该情况曾是静默的——运维设了标志却无从知道它未生效。
        // 两个限流器都解析：仅 --rateLimit 开时跳过这步
        // 使每个客户端键控到同一个键且告警保持静默。
        //
        if (resolved.forwardedIgnored || (opts.trustProxy !== true && req.headers['x-forwarded-for'])) {
          warnSharedBudget();
        }
      }
      // 在对照令牌之前检查，而非之后——耗尽的预算
      // 不评估猜测就答 429。仅限流 401 路径则什么也限不了：
      // 比较仍会发生、正确令牌仍被服务，状态码仍告诉攻击者
      // 哪个猜测是对的。
      if (authFailureLimiter) {
        const { allowed, retryAfterMs } = authFailureLimiter.peek(key);
        if (!allowed) {
          const retryAfterSec = Math.ceil(retryAfterMs / 1000);
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(retryAfterSec),
          });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32604,
              message: `Too many failed authentication attempts. Retry after ${retryAfterSec}s.`,
            },
            id: null,
          }));
          return;
        }
      }

      const auth = req.headers.authorization || '';
      const expected = `Bearer ${bearerToken}`;
      const authBuf = Buffer.from(auth);
      const expectedBuf = Buffer.from(expected);
      const match = authBuf.length === expectedBuf.length &&
        timingSafeEqual(authBuf, expectedBuf);
      if (!match) {
        authFailureLimiter?.recordFailure(key);
        // RFC 7235：401 必须说明如何认证。MCP 客户端也在此路由上
        // 解析 JSON-RPC 信封，401 与 429 和 413 说同样的方言
        // 而非裸 {error}。
        res.writeHead(401, {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="ssh-mcp"',
        });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Unauthorized' },
          id: null,
        }));
        return;
      }

      // 令牌检查之后计费，永不之前：请求桶按客户端，但
      // 未认证流量到达它可能以可伪造的键花掉受害者的预算，
      // 其 429 会在不评估猜测的情况下应答。每条已认证路由
      // 都从此消耗，含 /status 和 404：/status 过去无限制，
      // 令牌持有者可以无界轮询。
      if (rateLimiter) {
        const { allowed, retryAfterMs } = rateLimiter.tryConsume(key);
        if (!allowed) {
          const retryAfterSec = Math.ceil(retryAfterMs / 1000);
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(retryAfterSec),
          });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32604,
              message: `Rate limit exceeded. Retry after ${retryAfterSec}s.`,
            },
            id: null,
          }));
          return;
        }
      }
    }

    if (req.method === 'POST' && url.pathname === '/') {
      const body = new SizeCappedText(MAX_BODY_SIZE, () => {
        // Connection: close 是承重的不是装饰。没有它 keep-alive
        // 客户端（v19 起 Node 默认 agent）将套接字归还池，
        // 下方 destroy 杀死池中的套接字——客户端*下一个*
        // 请求以 EPIPE 失败。
        res.writeHead(413, {
          'Content-Type': 'application/json',
          'Connection': 'close',
        });
        // 413 冲刷后才 destroy；立即 destroy 与响应竞速，
        // 客户端看到裸连接重置而非告知原因的状态。
        //
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            error: { code: -32600, message: 'Request body too large (max 1MB)' },
            id: null,
          }),
          () => req.destroy(),
        );
      });
      req.on('data', (chunk) => body.append(chunk));
      req.on('end', async () => {
        if (body.overflow) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(body.value);
        } catch {
          jsonRpcError(res, 400, -32700, 'Parse error: invalid JSON');
          return;
        }
        await serveMcpRequest(req, res, parsed);
      });
      return;
    }

    if ((req.method === 'GET' || req.method === 'DELETE') && url.pathname === '/') {
      await serveMcpRequest(req, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'running',
        version: SERVER_VERSION,
        connections: registry.listConnections(),
        profiles: registry.listAllProfiles().map((p) => ({
          name: p.name,
          host: p.host,
          user: p.user,
          role: p.role,
          readOnly: p.readOnly,
        })),
        mcpSessions: sessionStats(),
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      // configured 是存活探针对就绪状态说的真话。服务器学会
      // 无配置启动后，配置 bind mount 静默没挂上的 HTTP 部署
      // 照常启动、绑端口、100% 工具调用失败——此探针却说
      // healthy: true，解释性的 stderr 告警在启动时滚过。
      // 状态保持 200 让已有探针不因升级开始失败；
      // 字段是运维可以告警的东西。
      //
      // 它将此未认证路由披露的内容恰好扩大一位，
      // 那一位对谁都价值有限：无 profile 的服务器是无法到达
      // 任何主机的服务器。/status 携带 profile 列表本身且在令牌之后。
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ healthy: true, configured: registry.listAllProfiles().length > 0 }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  httpServer.once('close', () => {
    void Promise.all(Array.from(sessions.values(), (session) => closeSession(session, 'transport-close')));
  });

  // 此前 listen() 无错误处理器，EADDRINUSE 以未处理 error 事件
  // 和裸堆栈浮出——且 startHttpServer 不管怎样都立即 resolve，
  // 调用方继续仿佛服务器已启动。
  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      // OperatorError 而非 Error：此处的每次 listen 失败都关于
      // 服务器如何被调用——端口已被占用、特权端口、拼错 --httpHost。
      // 留在缺陷路径打印堆栈并以 1 退出，在本代码库的规则下
      // 是邀运维把自己的端口选择报为 bug。
      //
      reject(new OperatorError(
        err.code === 'EADDRINUSE'
          ? `Cannot bind ${host}:${port} — address already in use.`
          : `Cannot bind ${host}:${port}: ${err.message}`,
      ));
    });
    httpServer.listen(port, host, () => {
      console.error(`SSH MCP Server v2 (HTTP) listening on http://${host}:${port}`);
      console.error('Endpoints: POST / (MCP), GET /status, GET /health');
      if (rateLimiter) {
        console.error(`Rate limit: ${opts.rateLimit} req/min per client`);
      }
      if (authFailureLimiter) {
        console.error(`Auth failure limit: ${authFailureLimit}/min per client`);
      }
      resolve();
    });
  });
  return httpServer;
}
