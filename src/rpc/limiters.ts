/**
 * 令牌桶限速器（T-13.5 预重构：自 src/transport/http.ts 原样迁入，零行为变化）。
 *
 * AuthFailureLimiter（认证失败限速）与 ClientRateLimiter（每客户端请求限速）
 * 共享同一套桶运算，使补充运算只存在一份。transport/http.ts 经 re-export
 * 保持既有导入面（test/unit/transport/http.test.ts 自 http.js 导入）；
 * T-15 删除 http.ts 后，导入方直接指向本模块。RPC 层（T-14）复用同一限速模式
 * （方案 §3.2：operator 会话认证失败限速）。
 */

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
