import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { isIP } from 'net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import { SERVER_VERSION } from '../version.js';
import { OperatorError } from '../errors.js';

const MAX_BODY_SIZE = 1_048_576; // 1MB
/** Cap on concurrent MCP sessions, so unauthenticated-adjacent churn can't grow the map without bound. */
const MAX_SESSIONS = 64;
/**
 * MCP 会话在被回收前可多长时间不收到请求。清理是惰性的，
 * 空闲服务器零成本，也没有需要清理的间隔。
 */
export const DEFAULT_SESSION_IDLE_TTL_MS = 30 * 60_000;

/** How many failed auth attempts one client may make per minute. 0 disables the check. */
export const DEFAULT_AUTH_FAILURE_LIMIT = 10;

/** Cap on tracked clients, for the reason `MAX_SESSIONS` exists: churn must not grow a map. */
export const MAX_TRACKED_CLIENTS = 1024;

const REFILL_INTERVAL_MS = 60_000;

interface Bucket {
  tokens: number;
  lastRefill: number;
}

/** Whole tokens earned since `lastRefill`. Negative when the clock stepped back; callers clamp. */
function tokensEarned(bucket: Bucket, maxTokens: number): number {
  return Math.floor(((Date.now() - bucket.lastRefill) / REFILL_INTERVAL_MS) * maxTokens);
}

/** Tokens the bucket would hold if refilled now, without changing it. */
function availableTokens(bucket: Bucket, maxTokens: number): number {
  return Math.min(maxTokens, bucket.tokens + Math.max(tokensEarned(bucket, maxTokens), 0));
}

/**
 * 到此桶赚到下一个令牌的时长，用于 Retry-After。
 *
 * 精确值，替代过去固定的 REFILL_INTERVAL_MS / maxTokens。那是
 * 一个令牌所需的时间，因此在间隔中途被拒的客户端被告知等待
 * 两倍于必要的时间。两侧有界：下限一秒，因为 Retry-After 是
 * 整秒且 0 读作「立即重试」；上限为一个令牌的间隔，因为
 * 时钟回拨使 lastRefill 落在未来，原始差值会宣告任意长的等待。
 * 向上取整到毫秒：除不尽一分钟的限额给出分数间隔，
 * 向下取整会指向令牌尚未到达的时刻。
 *
 */
function nextTokenWaitMs(bucket: Bucket, maxTokens: number): number {
  const interval = REFILL_INTERVAL_MS / maxTokens;
  return Math.max(1000, Math.ceil(Math.min(interval, bucket.lastRefill + interval - Date.now())));
}

/**
 * 补充后持有最多令牌的跟踪键：最不值得记住的条目，即要逐出的。
 *
 *
 * 用补充后的值而非存储值。停止发送的键永远保留存储计数，按 tokens
 * 排名会把一小时前花光的桶当成仍在花。曾经饱和一次的表
 * 就被永久判定为饱和——已实测。
 *
 * 表内线性，刻意保持：仅在新键到达满表时运行，
 * 在第一个满桶处提前停止。最坏情形——所有桶部分花费——
 * 在 1024 条目时每个新键约 46µs（Apple M4 Max, Node 24），
 * 两个限流器相同。
 */
function fullestBucket(
  buckets: Map<string, Bucket>,
  maxTokens: number,
): { key: string; available: number } | undefined {
  let fullest: { key: string; available: number } | undefined;
  for (const [key, bucket] of buckets) {
    const available = availableTokens(bucket, maxTokens);
    if (fullest === undefined || available > fullest.available) fullest = { key, available };
    if (available === maxTokens) break;
  }
  return fullest;
}

/**
 * 一步令牌桶操作，两个限流器共享使补充运算只存在一份。
 *
 * 修改桶。按经过时间成比例补充而非计时器，
 * 空闲服务器零成本，也没有需要清理的间隔。
 */
function consume(bucket: Bucket, maxTokens: number): { allowed: boolean; retryAfterMs: number } {
  const refilled = tokensEarned(bucket, maxTokens);
  if (refilled > 0) {
    bucket.tokens = Math.min(maxTokens, bucket.tokens + refilled);
    bucket.lastRefill += Math.round((refilled / maxTokens) * REFILL_INTERVAL_MS);
  }

  if (bucket.tokens > 0) {
    bucket.tokens--;
    return { allowed: true, retryAfterMs: 0 };
  }

  return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, maxTokens) };
}

/**
 * 每客户端一个请求桶，--rateLimit 意为每调用方每分钟 N 个请求。
 *
 * 之前是全进程一个桶：一个客户端为所有人花光 --rateLimit，
 * 未发送任何东西的客户端也被拒（#187，已实测）。以 clientKey() 为键，
 * 与失败预算同一键，且仅在令牌检查通过后计费，
 * 未认证流量无法创建条目或耗干他人预算。
 *
 * 有界如 AuthFailureLimiter，逐出最满桶的理由相同。
 * 差异：到达的键总是满启动，即使所有跟踪桶都已花光。
 * 饱和此表需要 1024 个持有令牌的地址，
 * 已有那么多地址的令牌持有者本来就有那么多预算。
 * 退款不开新口，而空启动会因他人流量拒绝
 * 合法客户端的第一个请求。
 */
export class ClientRateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private maxTokens: number) {}

  tryConsume(key: string): { allowed: boolean; retryAfterMs: number } {
    let bucket = this.buckets.get(key);
    if (bucket === undefined) {
      if (this.buckets.size >= MAX_TRACKED_CLIENTS) {
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
      }
      bucket = { tokens: this.maxTokens, lastRefill: Date.now() };
      this.buckets.set(key, bucket);
    }
    return consume(bucket, this.maxTokens);
  }
}

/**
 * 每客户端一个桶，用于限流认证失败。
 *
 * 刻意与请求限流器分离。认证检查先于请求限流器返回，
 * 错误 bearer 令牌不消耗任何东西，猜令牌以网络速度无退避运行——
 * 实测 --rateLimit=3 下 12 个 401、0 个 429。把请求限流器上移
 * 虽堵住此洞但开了更糟的：其 429 会在不评估猜测的情况下应答，
 * 且未认证流量到达请求桶可能以可伪造的键花掉受害者的预算。
 *
 *
 * 只有失败消耗令牌，正常客户端永不积累预算、
 * 也永远不会被自己的流量限流——这正是默认开启安全的原因。
 * 它不承诺正确令牌总是通过：地址一旦耗尽预算，
 * 来自该地址的一切都要等，正确令牌也不例外。
 * point. 在比较之后才计费会让猜测本身被评估，
 * 状态码仍会告诉攻击者哪个令牌是对的。
 */
export class AuthFailureLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private maxTokens: number) {}

  /** Whether this client may make another attempt. Does not consume. */
  peek(key: string): { allowed: boolean; retryAfterMs: number } {
    const bucket = this.buckets.get(key);
    if (bucket === undefined) return { allowed: true, retryAfterMs: 0 };
    if (availableTokens(bucket, this.maxTokens) > 0) return { allowed: true, retryAfterMs: 0 };
    return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, this.maxTokens) };
  }

  /** Charge this client for a failed attempt. */
  recordFailure(key: string): void {
    let bucket = this.buckets.get(key);
    if (bucket === undefined) {
      bucket = { tokens: this.maxTokens, lastRefill: Date.now() };
      if (this.buckets.size >= MAX_TRACKED_CLIENTS) {
        // Evict the *fullest* entry, not the oldest. An exhausted bucket has the oldest
        // `lastRefill` by construction, so evicting by age evicted the locked-out client
        // 然后又给它的键一份新预算：铸造足够多的键清除了锁定，
        // 端到端实测。满桶是唯一没有值得记住的东西的。
        //
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
        // 所有跟踪客户端都已花光，表本身就是信号，新键
        // 不会拿到满预算。
        //
        // 代价在此声明因为是真实的且无法软化：表饱和时
        // 到达的客户端只有一次尝试而非全部预算，
        // 第一次笔误就让正确令牌等待。播种一个令牌而非零
        // 看似有帮助实则没有——consume 立刻花掉它，
        // peek 本就允许从未见过的键，第一次尝试免费
        // 第二次被拒，两种播种结果相同。均已实测。
        // 给到达键真实预算正是本规则要阻止的退款。
        // 饱和需要 1024 个地址各自*最近*花光全部预算：
        // fullestBucket 按补充后排rank，条件在补充后即结束。
        if (fullest === undefined || fullest.available <= 0) bucket = { tokens: 0, lastRefill: Date.now() };
      }
      this.buckets.set(key, bucket);
    }
    consume(bucket, this.maxTokens);
  }
}

/**
 * 一次尝试计费到哪个客户端：chargedAddress 解析出的地址，
 * 由 keyOf 分组成键。只在此分组一次，使 header 逻辑的
 * 任何路径都无法交回未分组的地址——信任在内部决定，
 * 基于确切对端，在任何分组发生之前。
 */
export function clientKey(
  req: IncomingMessage,
  trustProxy: boolean,
  trustedProxies?: string[],
): { key: string; forwardedIgnored: boolean } {
  const { address, forwardedIgnored } = chargedAddress(req, trustProxy, trustedProxies);
  return { key: keyOf(address), forwardedIgnored };
}

/**
 * 一次尝试计费到的确切地址。
 *
 * 套接字的远程地址，直连时即真实客户端——本服务器的
 * 正常运行方式。X-Forwarded-For 仅在代理被显式信任时读取：
 * 无条件采信会让任何客户端伪造自己的键，
 * 从而完全绕开限制。
 *
 * 读取时取**最右**条目而非最左。代理追加它看到的地址，
 * 最右条目是最近受信代理观察到的，左侧全部来自客户端。
 * 读最左比没有限制更糟：发 X-Forwarded-For: 10.0.0.1 的客户端
 * 每次请求铸造新预算——实测九个错误令牌零 429——发受害者
 * 地址则烧*他们的*预算，锁死正确令牌。
 *
 *
 * 假定恰好一个受信代理在前，即 --trustProxy 的含义。两个的链
 * 需要倒数第二个，此处不猜深度。非 IP 地址一律丢弃
 * 而非用作映射键。
 */
function chargedAddress(
  req: IncomingMessage,
  trustProxy: boolean,
  trustedProxies?: string[],
): { address: string; forwardedIgnored: boolean } {
  const peer = canonicalAddress(req.socket.remoteAddress ?? 'unknown');
  const forwarded = req.headers['x-forwarded-for'];
  if (!trustProxy || forwarded === undefined) return { address: peer, forwardedIgnored: false };

  // 最右条目是代理写的仅当代理确实追加了。头部本身
  // 不说明是否如此，所以*对端*必须是代理——否则
  // 直达监听器的客户端发送一条伪造条目，该条目即最右，
  // 它自选键。此键控修复要阻止的两个攻击恰在该配置下复活。
  //
  if (!isTrustedPeer(peer, trustedProxies)) {
    return { address: peer, forwardedIgnored: true };
  }

  const raw = Array.isArray(forwarded) ? forwarded.join(',') : forwarded;
  const entries = raw.split(',').map((e) => e.trim()).filter(Boolean);
  const nearest = entries[entries.length - 1];
  const address = nearest === undefined ? undefined : forwardedAddress(nearest);
  if (address === undefined) return { address: peer, forwardedIgnored: true };
  return { address, forwardedIgnored: false };
}

/**
 * 地址计费到的键：IPv4 按自身，IPv6 按 /64。
 *
 * 用户通常至少分配一个 /64，/64 即客户端。提供商将多个客户
 * 放在同一 /64 时共享预算，如 IPv4 NAT 后的主机。
 *
 * 三个 IPv6 范围不是客户端自己的 /64 而是携带 IPv4 地址的方式，
 * 按那个地址键控：IPv4 映射 ::ffff:0:0/96 各种拼写、NAT64
 * 知名前缀 64:ff9b::/96 下转换部署看到的每个 IPv4 客户端、
 * 以及 IPv4 兼容 ::/96。按 /64 分组则每个都会把所有 IPv4
 * 客户端放到一个键上。使用自有前缀的转换器不被识别，
 * 其 IPv4 客户端共享该前缀的 /64。回环保持 ::1，无论拼写。
 */
function keyOf(address: string): string {
  if (isIP(address) !== 6) return address;
  const g = ipv6Groups(address);
  if (g.slice(0, 7).every((n) => n === 0) && g[7] === 1) return '::1';
  const lowZero = g[2] === 0 && g[3] === 0 && g[4] === 0;
  const carriesIpv4 = lowZero && (
    (g[0] === 0 && g[1] === 0 && (g[5] === 0 || g[5] === 0xffff)) ||
    (g[0] === 0x64 && g[1] === 0xff9b && g[5] === 0)
  );
  if (carriesIpv4) return `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
  return `${g.slice(0, 4).map((n) => n.toString(16)).join(':')}::/64`;
}

/**
 * IPv6 地址为其八个 16 位组，不论拼写：区域丢弃、::
 * 展开、点分 IPv4 尾读作最后两组、大小写和前导零由
 * 按数值读每组消除。期望 net.isIP 已接受的地址。
 */
function ipv6Groups(address: string): number[] {
  const [head, tail] = address.split('%')[0].split('::');
  const parse = (part: string | undefined): number[] =>
    part === undefined || part === ''
      ? []
      : part.split(':').flatMap((group) => {
        if (!group.includes('.')) return [parseInt(group, 16)];
        const [a, b, c, d] = group.split('.').map(Number);
        return [(a << 8) | b, (c << 8) | d];
      });
  const headGroups = parse(head);
  const tailGroups = parse(tail);
  if (tail === undefined) return headGroups;
  return [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill(0), ...tailGroups];
}

/**
 * 对端是否可以代表其他客户端说话。
 *
 * 裸 --trustProxy 意味着回环对端，即 README 要求的部署：
 * 服务器绑 127.0.0.1，同主机代理终结 TLS。别处的代理
 * 必须具名，因为「信任连接者」正是让头部可伪造的假设。
 *
 */
function isTrustedPeer(peer: string, trustedProxies?: string[]): boolean {
  if (trustedProxies !== undefined && trustedProxies.length > 0) {
    return trustedProxies.includes(peer);
  }
  return peer === '127.0.0.1' || peer === '::1' || peer.startsWith('127.');
}

/**
 * 一条 X-Forwarded-For 条目作为地址，非地址则为 undefined。
 *
 * net.isIP 拒绝带括号和端口后缀的拼写，IPv6 在此头部
 * 通常是那样出现的——拒绝静默把所有客户端折叠到代理的键上，
 * 比不键控还糟。
 */
function forwardedAddress(entry: string): string | undefined {
  let candidate = entry;
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);
  if (bracketed) candidate = bracketed[1];
  // 尾随 :port 仅当剩余部分不是 IPv6 字面量：::1 自有冒号，
  // 不得截断。
  else if (isIP(candidate) === 0 && /^[^:]+:\d+$/.test(candidate)) {
    candidate = candidate.slice(0, candidate.lastIndexOf(':'));
  }
  candidate = canonicalAddress(candidate);
  return isIP(candidate) === 0 ? undefined : candidate;
}

/**
 * ::ffff:127.0.0.1 和 127.0.0.1 是同一客户端；键控相同。
 *
 * 仅该拼写且后续为 IPv4 时：::ffff:c000:280 剥离为
 * c000:280 就不是地址了，请求回落到代理的键。映射地址
 * 其余拼写经 keyOf 按值到达 IPv4 键。
 * 大小写保留原样，因为这也是信任检查对照 --trustedProxies
 * 的对端——%WAN 这样的区域必须按写法匹配。
 */
function canonicalAddress(address: string): string {
  return address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
}

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
      let body = '';
      let bodyTooLarge = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
          if (!bodyTooLarge) {
            bodyTooLarge = true;
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
          }
        }
      });
      req.on('end', async () => {
        if (bodyTooLarge) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(body);
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
